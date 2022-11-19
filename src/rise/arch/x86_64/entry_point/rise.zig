const common = @import("common");
const assert = common.assert;
const logger = common.log.scoped(.EntryPoint);
const cpuid = common.arch.x86_64.cpuid;
const page_shifter = common.arch.page_shifter;
const valid_page_sizes = common.arch.valid_page_sizes;

const privileged = @import("privileged");
const Capabilities = privileged.Capabilities;
const CoreDirectorData = privileged.CoreDirectorData;
const CoreSupervisorData = privileged.CoreSupervisorData;
const CoreDirectorSharedGeneric = privileged.CoreDirectorSharedGeneric;
const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const PhysicalAddressSpace = privileged.PhysicalAddressSpace;
const SpawnState = privileged.SpawnState;
const VirtualAddress = privileged.VirtualAddress;
const VirtualAddressSpace = privileged.VirtualAddressSpace;
const UEFI = privileged.UEFI;

const APIC = privileged.arch.x86_64.APIC;
const GDT = privileged.arch.x86_64.GDT;
const IDT = privileged.arch.x86_64.IDT;
const paging = privileged.arch.paging;
const Syscall = privileged.arch.x86_64.Syscall;
const cr0 = privileged.arch.x86_64.registers.cr0;
const cr4 = privileged.arch.x86_64.registers.cr4;
const IA32_EFER = privileged.arch.x86_64.registers.IA32_EFER;
const IA32_PAT = privileged.arch.x86_64.registers.IA32_PAT;

const rise = @import("rise");

const MemoryMap = struct {
    const Entry = struct {
        physical_address: PhysicalAddress,
        size: u64,
        native_attributes: u64,
        tag: Type,
        const Type = enum {
            usable,
            bootloader_reserved,
            bootloader_information,
            bootloader_reclaimable,
            firmware_reserved,
            firmware_reclaimable,
            reserved,
        };
    };
};

export fn kernel_entry_point(bootloader_information: *UEFI.BootloaderInformation) noreturn {
    logger.debug("Hello kernel", .{});
    paging.register_physical_allocator(&rise.physical_allocator);
    IDT.setup();
    logger.debug("Loaded IDT", .{});

    // Claim some memory left from the bootloader

    var memory_map_iterator = bootloader_information.memory_map.iterator();
    var memory_map_conventional_entry_index: usize = 0;

    const entry_count = bootloader_information.counters.len;
    const physical_regions_allocation_size = @sizeOf(PhysicalAddressSpace.Region) * entry_count;

    const free_physical_regions = blk: {
        while (memory_map_iterator.next(bootloader_information.memory_map)) |entry| {
            if (entry.type == .ConventionalMemory) {
                const used_4k_page_count = bootloader_information.counters[memory_map_conventional_entry_index];
                const used_byte_count = used_4k_page_count << page_shifter(valid_page_sizes[0]);

                if (used_byte_count >= physical_regions_allocation_size) {
                    const physical_address = PhysicalAddress(.local).new(entry.physical_start + used_byte_count);
                    bootloader_information.counters[memory_map_conventional_entry_index] += @intCast(u32, common.align_forward(physical_regions_allocation_size, valid_page_sizes[0]) >> page_shifter(valid_page_sizes[0]));

                    const free_regions = physical_address.to_higher_half_virtual_address().access([*]PhysicalAddressSpace.Region)[0..entry_count];
                    memory_map_iterator.reset();
                    memory_map_conventional_entry_index = 0;

                    var maybe_previous: ?*PhysicalAddressSpace.Region = null;

                    while (memory_map_iterator.next(bootloader_information.memory_map)) |memory_map_entry| {
                        if (memory_map_entry.type == .ConventionalMemory) {
                            defer memory_map_conventional_entry_index += 1;

                            const entry_used_page_count = bootloader_information.counters[memory_map_conventional_entry_index];
                            const entry_used_byte_count = entry_used_page_count << page_shifter(valid_page_sizes[0]);

                            const entry_physical_address = PhysicalAddress(.local).new(memory_map_entry.physical_start + entry_used_byte_count);
                            const entry_free_page_count = memory_map_entry.number_of_pages - entry_used_page_count;
                            const entry_free_byte_count = entry_free_page_count << page_shifter(valid_page_sizes[0]);

                            if (entry_free_byte_count != 0) {
                                const region = &free_regions[memory_map_conventional_entry_index];
                                region.* = .{
                                    .descriptor = .{
                                        .address = entry_physical_address,
                                        .size = entry_free_byte_count,
                                    },
                                    .previous = maybe_previous,
                                    .next = null,
                                };

                                if (maybe_previous) |previous| {
                                    previous.next = region;
                                }

                                maybe_previous = region;
                            }
                        }
                    }

                    break :blk free_regions;
                }

                memory_map_conventional_entry_index += 1;
            }
        }

        @panic("Unable to find a host entry for physical regions");
    };

    logger.debug("Finished processing memory map", .{});

    rise.bootstrap_address_space = PhysicalAddressSpace{
        .free_list = .{
            .first = &free_physical_regions[0],
            .last = &free_physical_regions[free_physical_regions.len - 1],
            .count = free_physical_regions.len,
        },
    };

    const apic_base = APIC.init();

    // TODO: init RTC
    // TODO: setup timer properly
    if (common.config.timeslicing) {
        APIC.calibrate_timer(apic_base);
    } else {
        logger.warn("Timeslicing not enabled", .{});
        @panic("todo implement no timeslicing");
    }

    logger.warn("TODO: Enable IPI", .{});
    Syscall.enable(@ptrToInt(&kernel_syscall_entry_point));

    // Enable no-execute protection
    {
        var efer = IA32_EFER.read();
        efer.NXE = true;
        efer.write();
    }

    enable_fpu();
    enable_performance_counters();

    logger.warn("TODO: enabling TLB flush filter", .{});

    enable_global_pages();

    enable_monitor_mwait();

    configure_page_attribute_table();

    logger.debug("Reached to the end of the entry point", .{});

    kernel_startup(bootloader_information.init_file);
}

fn kernel_startup(init_file: []const u8) noreturn {
    if (APIC.is_bsp) {
        const core_director_data = spawn_bsp_init(init_file) catch |err| {
            privileged.panic("Can't spawn init: {}", .{err});
        };

        dispatch(core_director_data);
    } else {
        @panic("AP initialization");
    }
    privileged.arch.CPU_stop();
}

fn dispatch(core_director_data: *CoreDirectorData) noreturn {
    if (core_director_data != current_core_director_data) {
        core_director_data.context_switch();
        current_core_director_data = core_director_data;
    }

    const dispatcher_handle = core_director_data.dispatcher_handle;
    const dispatcher = dispatcher_handle.access(*CoreDirectorSharedGeneric);
    const disabled_area = dispatcher.get_disabled_save_area();
    logger.warn("todo: time", .{});

    switch (dispatcher.disabled != 0) {
        true => resume_state(disabled_area),
        false => @panic("not disabled"),
    }
}

fn resume_state(state: *privileged.arch.Registers) noreturn {
    asm volatile (
        \\pushq %[ss]
        \\pushq 7*8(%[registers])
        :
        : [ss] "i" (@offsetOf(GDT.Table, "user_data_64")),
          [registers] "r" (state),
    );
    @panic("resume state");
}

fn spawn_bsp_init(init_file: []const u8) !*CoreDirectorData {
    assert(APIC.is_bsp);
    const core_director_data = try spawn_init_common(&start_spawn_state);
    const executable_in_higher_half = try privileged.Executable.load_into_kernel_memory(&rise.bootstrap_address_space, init_file);
    const entry_point = try executable_in_higher_half.load_into_user_memory(&rise.physical_allocator);
    const init_dispatcher_x86_64 = core_director_data.dispatcher_handle.access(*privileged.arch.CoreDirectorShared);
    init_dispatcher_x86_64.disabled_save_area.rip = entry_point;
    logger.debug("Entry point: 0x{x}", .{entry_point});
    logger.warn("implement capabilities", .{});
    return core_director_data;
}

fn spawn_init_common(spawn_state: *SpawnState) !*CoreDirectorData {
    const core_director_data = try spawn_module(spawn_state);
    var virtual_address_space = init_page_tables(spawn_state);
    const init_dispatcher = core_director_data.dispatcher_handle.access(*CoreDirectorSharedGeneric);
    const init_dispatcher_x86_64 = core_director_data.dispatcher_handle.access(*privileged.arch.CoreDirectorShared);
    core_director_data.vspace = @bitCast(usize, privileged.arch.x86_64.registers.cr3.read());
    core_director_data.disabled = true;
    //init_dispatcher_x86_64.enabled_save_area.set_param
    _ = init_dispatcher_x86_64;
    _ = init_dispatcher;
    _ = virtual_address_space;
    return core_director_data;
}

fn init_page_tables(spawn_state: *SpawnState) VirtualAddressSpace {
    _ = spawn_state;
    const address_space = VirtualAddressSpace.user(&rise.bootstrap_address_space);
    address_space.make_current();
    return address_space;
}

var core_supervisor_data: CoreSupervisorData = undefined;
export var current_core_supervisor_data = &core_supervisor_data;
export var current_core_director_data: *CoreDirectorData = undefined;

fn spawn_module(spawn_state: *SpawnState) !*CoreDirectorData {
    const root_cn = cnode_many_ptr(&current_core_supervisor_data.init_rootcn);
    try privileged.MappingDatabase.init(current_core_supervisor_data);
    current_core_supervisor_data.is_valid = true;

    try Capabilities.new(.l1cnode, (try rise.bootstrap_address_space.allocate(Capabilities.Size.l2cnode, valid_page_sizes[0])).address, Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, rise.core_id, root_cn);

    // TODO: @ArchIndependent
    //if (APIC.is_bsp) {
    //const bsp_kernel_control_block_capability = Capabilities.Capability{
    //.object = .{
    //.kernel_control_block = current_core_supervisor_data,
    //},
    //.rights = Capabilities.Rights.all,
    //.type = .kernel_control_block,
    //};
    //const bsp_kernel_control_block = Capabilities.locate_slot(root_cn[0].get_cnode().to_local(), @enumToInt(Capabilities.RootCNodeSlot.bsp_kernel_control_block));
    //assert(bsp_kernel_control_block.capability.type == .null);
    //bsp_kernel_control_block.capability = bsp_kernel_control_block_capability;
    //}

    //logger.debug("cnode: task", .{});
    spawn_state.cnodes.task = Capabilities.locate_slot(root_cn[0].get_cnode().to_local(), @enumToInt(Capabilities.RootCNodeSlot.task));
    try Capabilities.new(.l2cnode, (try rise.bootstrap_address_space.allocate(Capabilities.Size.l2cnode, valid_page_sizes[0])).address, Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, rise.core_id, cnode_many_ptr(spawn_state.cnodes.task orelse unreachable));

    //logger.debug("cnode: page", .{});
    //spawn_state.cnodes.page = Capabilities.locate_slot(root_cn[0].get_cnode().to_local(), @enumToInt(Capabilities.RootCNodeSlot.page));
    //try Capabilities.new(.l2cnode, (try rise.bootstrap_address_space.allocate(Capabilities.Size.l2cnode, valid_page_sizes[0])).address, Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, rise.core_id, cnode_many_ptr(spawn_state.cnodes.page orelse unreachable));

    //logger.debug("cnode: base_page", .{});
    //spawn_state.cnodes.base_page = Capabilities.locate_slot(root_cn[0].get_cnode().to_local(), @enumToInt(Capabilities.RootCNodeSlot.base_page));
    //try Capabilities.new(.l2cnode, (try rise.bootstrap_address_space.allocate(Capabilities.Size.l2cnode, valid_page_sizes[0])).address, Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, rise.core_id, cnode_many_ptr(spawn_state.cnodes.base_page orelse unreachable));

    //logger.debug("cnode: early_cnode", .{});
    //spawn_state.cnodes.early_cnode = Capabilities.locate_slot(root_cn[0].get_cnode().to_local(), @enumToInt(Capabilities.RootCNodeSlot.early_cnode));
    //try Capabilities.new(.l2cnode, (try rise.bootstrap_address_space.allocate(Capabilities.Size.l2cnode, valid_page_sizes[0])).address, Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, rise.core_id, cnode_many_ptr(spawn_state.cnodes.early_cnode orelse unreachable));

    //logger.debug("cnode: super", .{});
    //spawn_state.cnodes.super = Capabilities.locate_slot(root_cn[0].get_cnode().to_local(), @enumToInt(Capabilities.RootCNodeSlot.super));
    //try Capabilities.new(.l2cnode, (try rise.bootstrap_address_space.allocate(Capabilities.Size.l2cnode, valid_page_sizes[0])).address, Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, rise.core_id, cnode_many_ptr(spawn_state.cnodes.super orelse unreachable));

    //logger.debug("cnode: slot_alloc", .{});
    //spawn_state.cnodes.slot_alloc0 = Capabilities.locate_slot(root_cn[0].get_cnode().to_local(), @enumToInt(Capabilities.RootCNodeSlot.slot_alloc0));
    //try Capabilities.new(.l2cnode, (try rise.bootstrap_address_space.allocate(4 * Capabilities.Size.l2cnode, valid_page_sizes[0])).address, 4 * Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, rise.core_id, cnode_many_ptr(spawn_state.cnodes.slot_alloc0 orelse unreachable));

    //logger.debug("cnode: seg", .{});
    //spawn_state.cnodes.seg = Capabilities.locate_slot(root_cn[0].get_cnode().to_local(), @enumToInt(Capabilities.RootCNodeSlot.seg));
    //try Capabilities.new(.l2cnode, (try rise.bootstrap_address_space.allocate(Capabilities.Size.l2cnode, valid_page_sizes[0])).address, Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, rise.core_id, cnode_many_ptr(spawn_state.cnodes.seg orelse unreachable));

    //logger.debug("cnode: physical_address", .{});
    //spawn_state.cnodes.physical_address = Capabilities.locate_slot(root_cn[0].get_cnode().to_local(), @enumToInt(Capabilities.RootCNodeSlot.physical_address));
    //try Capabilities.new(.l2cnode, (try rise.bootstrap_address_space.allocate(Capabilities.Size.l2cnode, valid_page_sizes[0])).address, Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, rise.core_id, cnode_many_ptr(spawn_state.cnodes.physical_address orelse unreachable));

    //// TODO @ArchIndependent
    //if (APIC.is_bsp) {
    //logger.debug("cnode: module", .{});
    //spawn_state.cnodes.module = Capabilities.locate_slot(root_cn[0].get_cnode().to_local(), @enumToInt(Capabilities.RootCNodeSlot.module));
    //try Capabilities.new(.l2cnode, (try rise.bootstrap_address_space.allocate(Capabilities.Size.l2cnode, valid_page_sizes[0])).address, Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, rise.core_id, cnode_many_ptr(spawn_state.cnodes.module orelse unreachable));
    //}

    //logger.debug("cnode: init dcb", .{});
    const init_dcb_cte = Capabilities.locate_slot(spawn_state.cnodes.task.?.get_cnode().to_local(), @enumToInt(Capabilities.TaskCNodeSlot.dispatcher));
    try Capabilities.new(.dispatcher, (try rise.bootstrap_address_space.allocate(Capabilities.Size.dispatcher, valid_page_sizes[0])).address, Capabilities.Size.dispatcher, 0, rise.core_id, cnode_many_ptr(init_dcb_cte));

    const init_dispatcher_data = init_dcb_cte.capability.object.dispatcher.current;

    //try root_cn[0].copy_to_cnode(spawn_state.cnodes.task orelse unreachable, @enumToInt(Capabilities.TaskCNodeSlot.root), false, 0, 0);

    const init_dispatcher_frame_cte = Capabilities.locate_slot(spawn_state.cnodes.task.?.get_cnode().to_local(), @enumToInt(Capabilities.TaskCNodeSlot.dispatcher_frame));
    try Capabilities.new(.frame, (try rise.bootstrap_address_space.allocate(Capabilities.dispatcher_frame_size, Capabilities.dispatcher_frame_size)).address, Capabilities.dispatcher_frame_size, Capabilities.dispatcher_frame_size, rise.core_id, cnode_many_ptr(init_dispatcher_frame_cte));

    try init_dispatcher_frame_cte.copy_to_cte(&init_dispatcher_data.dispatcher_cte, false, 0, 0);

    //const init_args_cte = Capabilities.locate_slot(spawn_state.cnodes.task.?.get_cnode().to_local(), @enumToInt(Capabilities.TaskCNodeSlot.args_space));
    //try Capabilities.new(.frame, (try rise.bootstrap_address_space.allocate(Capabilities.args_size, Capabilities.args_size)).address, Capabilities.args_size, Capabilities.args_size, rise.core_id, cnode_many_ptr(init_args_cte));
    //spawn_state.argument_page_address = init_args_cte.capability.object.frame.base.to_local();

    //// TODO @ArchIndependent
    //if (APIC.is_bsp) {
    //logger.warn("todo: bootloader information", .{});
    //}

    //const kernel_cap_cte = Capabilities.locate_slot(spawn_state.cnodes.task.?.get_cnode().to_local(), @enumToInt(Capabilities.TaskCNodeSlot.kernel_cap));
    //try Capabilities.new(.kernel, .null, 0, 0, rise.core_id, cnode_many_ptr(kernel_cap_cte));

    //const performance_monitor_cap_cte = Capabilities.locate_slot(spawn_state.cnodes.task.?.get_cnode().to_local(), @enumToInt(Capabilities.TaskCNodeSlot.performance_monitor));
    //try Capabilities.new(.performance_monitor, .null, 0, 0, rise.core_id, cnode_many_ptr(performance_monitor_cap_cte));

    //const irq_table_cap_cte = Capabilities.locate_slot(spawn_state.cnodes.task.?.get_cnode().to_local(), @enumToInt(Capabilities.TaskCNodeSlot.irq));
    //try Capabilities.new(.irq_table, .null, 0, 0, rise.core_id, cnode_many_ptr(irq_table_cap_cte));

    //const ipi_cap_cte = Capabilities.locate_slot(spawn_state.cnodes.task.?.get_cnode().to_local(), @enumToInt(Capabilities.TaskCNodeSlot.ipi));
    //try Capabilities.new(.ipi, .null, 0, 0, rise.core_id, cnode_many_ptr(ipi_cap_cte));

    //const process_manager_cap_cte = Capabilities.locate_slot(spawn_state.cnodes.task.?.get_cnode().to_local(), @enumToInt(Capabilities.TaskCNodeSlot.process_manager));
    //try Capabilities.new(.process_manager, .null, 0, 0, rise.core_id, cnode_many_ptr(process_manager_cap_cte));

    const init_handle = init_dispatcher_frame_cte.capability.object.frame.base.to_higher_half_virtual_address();
    //const &init_handle.access(*arch.Dispatcher).base;
    const init_core_director = init_handle.access(*CoreDirectorSharedGeneric);
    init_core_director.disabled = @boolToInt(true);
    init_core_director.core_id = rise.core_id;

    try root_cn[0].copy_to_cte(&init_dispatcher_data.cspace, false, 0, 0);

    init_dispatcher_data.dispatcher_handle = init_handle.to_local();
    init_dispatcher_data.disabled = true;
    privileged.Scheduler.make_runnable(init_dispatcher_data);

    logger.warn("todo: enable ALL capabilities", .{});

    //const base_page_cn_cte = Capabilities.locate_slot(spawn_state.cnodes.base_page.?.get_cnode().to_local(), 0);
    //try Capabilities.new(.ram, (try rise.bootstrap_address_space.allocate(Capabilities.l2_cnode_slots * valid_page_sizes[0], valid_page_sizes[0])).address, Capabilities.l2_cnode_slots * valid_page_sizes[0], valid_page_sizes[0], rise.core_id, cnode_many_ptr(base_page_cn_cte));
    //logger.debug("base page", .{});

    //const early_cnode_cn_cte = Capabilities.locate_slot(spawn_state.cnodes.early_cnode.?.get_cnode().to_local(), 0);
    //try Capabilities.new(.ram, (try rise.bootstrap_address_space.allocate(Capabilities.early_cnode_allocated_slots * Capabilities.Size.l2cnode, valid_page_sizes[0])).address, Capabilities.early_cnode_allocated_slots * Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, rise.core_id, cnode_many_ptr(early_cnode_cn_cte));
    //logger.debug("early cnode", .{});

    return init_dispatcher_data;
}

fn cnode_many_ptr(cnode: *Capabilities.CTE) [*]Capabilities.CTE {
    const result = @ptrCast([*]Capabilities.CTE, cnode);
    return result;
}

pub var start_spawn_state = SpawnState{};

fn configure_page_attribute_table() void {
    logger.debug("Configuring page attribute table...", .{});
    defer logger.debug("Page attribute table configured!", .{});
    var pat = IA32_PAT.read();
    pat.page_attributes[4] = .write_combining;
    pat.page_attributes[5] = .write_protected;
    pat.write();
}

fn enable_global_pages() void {
    logger.debug("Enabling global pages...", .{});
    defer logger.debug("Global pages enabled!", .{});
    var my_cr4 = cr4.read();
    my_cr4.page_global_enable = true;
    my_cr4.write();
}

fn enable_monitor_mwait() void {
    // This is just reporting if it's available
    const supported = monitor_mwait.is_supported();
    logger.debug("mwait support: {}", .{supported});
}

var monitor_mwait: struct {
    supported: bool = false,
    called: bool = false,

    pub fn is_supported(mwait: *@This()) bool {
        if (!mwait.called) {
            const result = cpuid(1);
            mwait.supported = result.ecx & (1 << 3) != 0;
            mwait.called = true;
        }

        return mwait.supported;
    }
} = .{};

fn enable_performance_counters() void {
    logger.debug("Enabling performance counters...", .{});
    defer logger.debug("Performance counters enabled!", .{});
    var my_cr4 = cr4.read();
    my_cr4.performance_monitoring_counter_enable = true;
    my_cr4.write();
}

fn enable_fpu() void {
    logger.debug("Enabling FPU...", .{});
    defer logger.debug("FPU enabled!", .{});
    var my_cr0 = cr0.read();
    my_cr0.emulation = false;
    my_cr0.monitor_coprocessor = true;
    my_cr0.numeric_error = true;
    my_cr0.task_switched = false;
    my_cr0.write();
    var my_cr4 = cr4.read();
    my_cr4.operating_system_support_for_fx_save_restore = true;
    my_cr4.write();

    asm volatile ("fninit");
    // should we ldmxcsr ?
}

pub const log_level = common.log.Level.debug;

pub fn log(comptime level: common.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
    writer.writeAll(prefix) catch unreachable;

    writer.print(format, args) catch unreachable;
    writer.writeByte('\n') catch unreachable;
}

pub fn panic(message: []const u8, _: ?*common.StackTrace, _: ?usize) noreturn {
    asm volatile (
        \\cli
    );
    common.log.scoped(.PANIC).err("{s}", .{message});
    privileged.arch.CPU_stop();
}

const Writer = common.Writer(void, error{}, e9_write);
const writer = Writer{ .context = {} };
fn e9_write(_: void, bytes: []const u8) error{}!usize {
    const bytes_left = asm volatile (
        \\cld
        \\rep outsb
        : [ret] "={rcx}" (-> usize),
        : [dest] "{dx}" (0xe9),
          [src] "{rsi}" (bytes.ptr),
          [len] "{rcx}" (bytes.len),
    );
    return bytes.len - bytes_left;
}

// TODO: implement syscall
pub export fn kernel_syscall_entry_point() callconv(.Naked) void {
    // This function only modifies RSP. The other registers are preserved in user space
    // This sets up the kernel stack before actually starting to run kernel code
    //asm volatile (
    //\\swapgs
    //// Save RFLAGS (R11), next instruction address after sysret (RCX) and user stack (RSP)
    //\\mov %%r11, %%r12
    //\\mov %%rcx, %%r13
    //\\mov %%rsp, %%r14
    //// Pass original RCX (4th argument)
    //\\mov %%rax, %%rcx
    //// Get kernel stack
    //\\mov %%gs:[0], %%r15
    //\\add %[offset], %%r15
    //\\mov (%%r15), %%r15
    //\\mov %%r15, %%rbp
    //// Use kernel stack
    //\\mov %%rbp, %%rsp
    //// Call the syscall handler
    //\\mov %[handler], %%rax
    //\\call *(%%rax)
    //// Restore RSP, R11 (RFLAGS) and RCX (RIP after sysret)
    //\\mov %%r14, %%rsp
    //\\mov %%r12, %%r11
    //\\mov %%r13, %%rcx
    //// Restore user GS
    //\\swapgs
    //// Go back to user mode
    //\\sysretq
    //:
    //: [offset] "i" (@intCast(u8, @offsetOf(Thread, "kernel_stack"))),
    //[handler] "i" (&Syscall.handler),
    //);

    @panic("reached unreachable: syscall handler");
}
