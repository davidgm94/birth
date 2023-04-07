const lib = @import("lib");
const Allocator = lib.Allocator;
const assert = lib.assert;
const log = lib.log;

const privileged = @import("privileged");
const stopCPU = privileged.arch.stopCPU;
const Mapping = privileged.Mapping;
const PageAllocator = privileged.PageAllocator;
const PageAllocatorInterface = privileged.PageAllocatorInterface;
const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalAddressSpace = privileged.PhysicalAddressSpace;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const VirtualAddress = privileged.VirtualAddress;
const VirtualMemoryRegion = privileged.VirtualMemoryRegion;

pub const scheduler_type = SchedulerType.round_robin;

pub const Scheduler = switch (scheduler_type) {
    .round_robin => @import("cpu/round_robin.zig"),
    else => @compileError("other scheduler is not supported right now"),
};

pub const SchedulerType = enum(u8) {
    round_robin,
    rate_based_earliest_deadline,
};

const bootloader = @import("bootloader");

pub const test_runner = @import("cpu/test_runner.zig");

pub const arch = @import("cpu/arch.zig");
pub const Capabilities = @import("cpu/capabilities.zig");
pub const MappingDatabase = @import("cpu/mapping_database.zig");

pub export var stack: [0x4000]u8 align(0x1000) = undefined;
pub export var address_space: VirtualAddressSpace = undefined;
pub export var core_id: u8 = 0;
pub export var spawn_state = SpawnState{};

pub var bsp = false;

pub export var mappings: extern struct {
    text: privileged.Mapping = .{},
    rodata: privileged.Mapping = .{},
    data: privileged.Mapping = .{},
} = .{};

pub export var page_allocator = PageAllocator{
    .head = null,
    .list_allocator = .{
        .u = .{
            .primitive = .{
                .backing_4k_page = undefined,
                .allocated = 0,
            },
        },
        .primitive = true,
    },
};

pub export var heap_allocator = Heap{};

pub const Heap = extern struct {
    region: VirtualMemoryRegion = .{
        .address = .null,
        .size = 0,
    },

    pub fn fromPageAllocator(pa: *PageAllocator) !Heap {
        const physical_allocation = try pa.allocate(lib.arch.valid_page_sizes[1], lib.arch.valid_page_sizes[1]);
        const virtual_allocation = physical_allocation.toHigherHalfVirtualAddress();
        return Heap{
            .region = virtual_allocation,
        };
    }

    pub inline fn allocate(heap: *Heap, comptime T: type, count: usize) Allocator.Allocate.Error!*T {
        const region = try heap.allocateBytes(@sizeOf(T) * count, @alignOf(T));
        return region.access(T);
    }

    pub inline fn create(heap: *Heap, comptime T: type) Allocator.Allocate.Error!*T {
        const region = try heap.allocateBytes(@sizeOf(T), @alignOf(T));
        return region.address.access(*T);
    }

    pub noinline fn allocateBytes(heap: *Heap, size: u64, alignment: u64) Allocator.Allocate.Error!VirtualMemoryRegion {
        if (heap.region.size == 0) {
            const region_allocation = try page_allocator.allocate(lib.arch.valid_page_sizes[0], lib.arch.valid_page_sizes[0]);
            const virtual_region = region_allocation.toHigherHalfVirtualAddress();
            heap.region = virtual_region;
        }

        if (heap.region.size < size) {
            @panic("size too big");
        }

        if (!lib.isAligned(heap.region.address.value(), alignment)) {
            @panic("alignment too big");
        }

        const result_address = heap.region.address;
        heap.region.size -= size;
        heap.region.address = heap.region.address.offset(size);

        return .{
            .address = result_address,
            .size = size,
        };
    }

    pub const Entry = PageAllocator.Entry;
};

pub const writer = arch.writer;
var panic_lock = arch.Spinlock.released;

inline fn panicPrologue(comptime format: []const u8, arguments: anytype) void {
    privileged.arch.disableInterrupts();
    panic_lock.acquire();

    writer.writeAll("[CPU DRIVER] [PANIC] ") catch stopCPU();
    writer.print(format, arguments) catch stopCPU();
    writer.writeByte('\n') catch stopCPU();
}

inline fn panicEpilogue() noreturn {
    panic_lock.release();

    if (lib.is_test) {
        log.debug("Exiting from QEMU...", .{});
        privileged.exitFromQEMU(.failure);
    } else {
        log.debug("Not exiting from QEMU...", .{});
        privileged.arch.stopCPU();
    }
}

inline fn panicPrintStackTrace(maybe_stack_trace: ?*lib.StackTrace) void {
    if (maybe_stack_trace) |stack_trace| {
        writer.writeAll("Stack trace:\n") catch stopCPU();
        var frame_index: usize = 0;
        var frames_left: usize = @min(stack_trace.index, stack_trace.instruction_addresses.len);

        while (frames_left != 0) : ({
            frames_left -= 1;
            frame_index = (frame_index + 1) % stack_trace.instruction_addresses.len;
        }) {
            const return_address = stack_trace.instruction_addresses[frame_index];
            writer.print("[{}] 0x{x}\n", .{ frame_index, return_address }) catch stopCPU();
        }
    } else {
        writer.writeAll("Stack trace not available\n") catch stopCPU();
    }
}

inline fn panicPrintStackTraceFromStackIterator(return_address: usize, frame_address: usize) void {
    var stack_iterator = lib.StackIterator.init(return_address, frame_address);
    var frame_index: usize = 0;
    writer.writeAll("Stack trace:\n") catch stopCPU();
    while (stack_iterator.next()) |ra| : (frame_index += 1) {
        writer.print("[{}] 0x{x}\n", .{ frame_index, ra }) catch stopCPU();
    }
}

pub fn panicWithStackTrace(stack_trace: ?*lib.StackTrace, comptime format: []const u8, arguments: anytype) noreturn {
    panicPrologue(format, arguments);
    panicPrintStackTrace(stack_trace);
    panicEpilogue();
}

pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    panicPrologue(format, arguments);
    panicPrintStackTraceFromStackIterator(@returnAddress(), @frameAddress());
    panicEpilogue();
}

pub const UserVirtualAddressSpace = extern struct {
    generic: VirtualAddressSpace,
};

pub const VirtualAddressSpace = extern struct {
    arch: paging.Specific,
    page: Page = .{},
    heap: Heap = .{},
    options: packed struct(u64) {
        user: bool,
        mapped_page_tables: bool,
        log_pages: bool,
        reserved: u61 = 0,
    },

    const Context = extern struct {
        region_base: u64 = 0,
        size: u64 = 0,
    };

    const Page = extern struct {
        context: Context = .{},
        log: ?*PageAllocator.Entry = null,
        log_count: u64 = 0,
    };

    const VAS = @This();

    pub const paging = switch (lib.cpu.arch) {
        .x86 => privileged.arch.x86_64.paging,
        else => privileged.arch.current.paging,
    };

    fn callbackHeapAllocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
        _ = alignment;
        _ = size;
        if (lib.cpu.arch != .x86) {
            const virtual_address_space = @fieldParentPtr(VirtualAddressSpace, "heap", @fieldParentPtr(Heap, "allocator", allocator));
            _ = virtual_address_space;
        } else {
            return Allocator.Allocate.Error.OutOfMemory;
        }
    }
    //

    pub fn user(physical_address_space: *PhysicalAddressSpace) VAS {
        // TODO: defer memory free when this produces an error
        // TODO: Maybe consume just the necessary space? We are doing this to avoid branches in the kernel heap allocator
        var vas = VAS{
            .arch = undefined,
        };

        paging.init_user(&vas, physical_address_space);

        return vas;
    }

    pub inline fn makeCurrent(vas: *const VAS) void {
        paging.makeCurrent(vas);
    }

    pub fn map(virtual_address_space: *VirtualAddressSpace, asked_physical_address: PhysicalAddress, asked_virtual_address: VirtualAddress, size: u64, general_flags: Mapping.Flags) !void {
        // TODO: use flags

        // if (!asked_physical_address.isValid()) return Error.invalid_physical;
        // if (!asked_virtual_address.isValid()) return Error.invalid_virtual;
        if (size == 0) {
            return paging.Error.invalid_size;
        }

        if (!lib.isAlignedGeneric(u64, asked_physical_address.value(), lib.arch.valid_page_sizes[0])) {
            return paging.Error.unaligned_physical;
        }

        if (!lib.isAlignedGeneric(u64, asked_virtual_address.value(), lib.arch.valid_page_sizes[0])) {
            return paging.Error.unaligned_virtual;
        }

        if (!lib.isAlignedGeneric(u64, size, lib.arch.valid_page_sizes[0])) {
            return paging.Error.unaligned_size;
        }

        if (asked_physical_address.value() >= lib.config.cpu_driver_higher_half_address) {
            return paging.Error.invalid_physical;
        }

        try virtual_address_space.arch.map(asked_physical_address, asked_virtual_address, size, general_flags, virtual_address_space.getPageAllocatorInterface());
    }

    pub inline fn mapDevice(virtual_address_space: *VirtualAddressSpace, asked_physical_address: PhysicalAddress, size: u64) !VirtualAddress {
        try virtual_address_space.map(asked_physical_address, asked_physical_address.toHigherHalfVirtualAddress(), size, .{
            .write = true,
            .cache_disable = true,
            .global = false,
        });

        return asked_physical_address.toHigherHalfVirtualAddress();
    }

    pub fn allocatePages(virtual_address_space: *VirtualAddressSpace, size: u64, alignment: u64, options: PageAllocatorInterface.AllocateOptions) Allocator.Allocate.Error!PhysicalMemoryRegion {
        _ = options;
        if (virtual_address_space.page.context.size == 0) {
            if (alignment > lib.arch.valid_page_sizes[1]) return Allocator.Allocate.Error.OutOfMemory;
            // Try to allocate a bigger bulk so we don't have to use the backing allocator (slower) everytime a page is needed
            const selected_size = @max(size, lib.arch.valid_page_sizes[1]);
            const selected_alignment = @max(alignment, lib.arch.valid_page_sizes[1]);

            const page_bulk_allocation = page_allocator.allocate(selected_size, selected_alignment) catch blk: {
                if (alignment > lib.arch.valid_page_sizes[0]) return Allocator.Allocate.Error.OutOfMemory;
                break :blk try page_allocator.allocate(size, alignment);
            };

            virtual_address_space.page.context = .{
                .region_base = page_bulk_allocation.address.value(),
                .size = page_bulk_allocation.size,
            };

            if (virtual_address_space.options.log_pages) {
                try virtual_address_space.addPage(page_bulk_allocation);
            }
        }

        assert(virtual_address_space.page.context.region_base != 0);

        const allocation_result = .{
            .address = PhysicalAddress.new(virtual_address_space.page.context.region_base),
            .size = size,
        };

        if (!lib.isAlignedGeneric(u64, allocation_result.address.value(), alignment)) return Allocator.Allocate.Error.OutOfMemory;

        virtual_address_space.page.context.region_base += size;
        virtual_address_space.page.context.size -= size;

        return allocation_result;
    }
    fn callbackAllocatePages(context: ?*anyopaque, size: u64, alignment: u64, options: PageAllocatorInterface.AllocateOptions) Allocator.Allocate.Error!PhysicalMemoryRegion {
        const virtual_address_space = @ptrCast(*VirtualAddressSpace, @alignCast(@alignOf(VirtualAddressSpace), context));
        return try virtual_address_space.allocatePages(size, alignment, options);
    }

    pub fn mapPageTables(virtual_address_space: *VirtualAddressSpace) !void {
        assert(virtual_address_space.options.log_pages);

        var maybe_page_table_entry = virtual_address_space.page.log;
        while (maybe_page_table_entry) |page_table_entry| : (maybe_page_table_entry = page_table_entry.next) {
            try virtual_address_space.map(page_table_entry.region.address, page_table_entry.region.address.toIdentityMappedVirtualAddress(), page_table_entry.region.size, .{
                .user = true,
                .write = true,
            });
        }
        assert(virtual_address_space.page.log.?.next == null);

        virtual_address_space.options.mapped_page_tables = true;
    }

    pub fn addPage(virtual_address_space: *VirtualAddressSpace, region: PhysicalMemoryRegion) !void {
        const new_entry = try virtual_address_space.heap.create(PageAllocator.Entry);
        new_entry.* = .{
            .region = region,
            .next = virtual_address_space.page.log,
        };
        virtual_address_space.page.log = new_entry;

        virtual_address_space.page.log_count += 1;
    }

    pub inline fn validate(virtual_address_space: *VirtualAddressSpace) !void {
        try paging.validate(virtual_address_space);
    }

    pub inline fn translateAddress(virtual_address_space: *VirtualAddressSpace, virtual_address: VirtualAddress) !PhysicalAddress {
        const physical_address = try paging.translateAddress(virtual_address_space.arch, virtual_address);
        return physical_address;
    }

    pub fn getPageAllocatorInterface(virtual_address_space: *VirtualAddressSpace) PageAllocatorInterface {
        return .{
            .allocate = VirtualAddressSpace.callbackAllocatePages,
            .context = virtual_address_space,
            .context_type = .cpu,
        };
    }
};

pub const CoreSupervisorData = extern struct {
    is_valid: bool,
    next: ?*CoreSupervisorData,
    previous: ?*CoreSupervisorData,
    mdb_root: VirtualAddress,
    init_root_capability_node: Capabilities.CTE,
    scheduler_state: Scheduler.State,
    kernel_offset: i64,
    irq_in_use: [arch.dispatch_count]u8, // bitmap of handed out caps
    irq_dispatch: [arch.dispatch_count]Capabilities.CTE,
    pending_ram_in_use: u8,
    pending_ram: [4]RAM,
};

const RAM = extern struct {
    base: u64,
    bytes: u64,
};

pub const PassId = u32;
pub const CoreId = u8;
pub const CapAddr = u32;

const CTE = Capabilities.CTE;
pub const SpawnState = extern struct {
    cnodes: extern struct {
        task: ?*CTE = null,
        seg: ?*CTE = null,
        super: ?*CTE = null,
        physical_address: ?*CTE = null,
        module: ?*CTE = null,
        page: ?*CTE = null,
        base_page: ?*CTE = null,
        early_cnode: ?*CTE = null,
        slot_alloc0: ?*CTE = null,
        slot_alloc1: ?*CTE = null,
        slot_alloc2: ?*CTE = null,
    } = .{},
    slots: extern struct {
        seg: Capabilities.Slot = 0,
        super: Capabilities.Slot = 0,
        physical_address: Capabilities.Slot = 0,
        module: Capabilities.Slot = 0,
    } = .{},
    argument_page_address: PhysicalAddress = PhysicalAddress.maybeInvalid(0),
};

pub var current_supervisor: ?*CoreSupervisorData = null;
pub var current_director: ?*CoreDirectorData = null;

pub const CoreDirectorData = extern struct {
    shared: *CoreDirectorSharedGeneric,
    disabled: bool,
    cspace: CTE,
    virtual_address_space: ?*VirtualAddressSpace,
    dispatcher_cte: CTE,
    faults_taken: u32,
    is_vm_guest: bool,
    // TODO: guest desc
    domain_id: u64,
    // TODO: wakeup time
    wakeup_previous: ?*CoreDirectorData,
    wakeup_next: ?*CoreDirectorData,
    next: ?*CoreDirectorData,
    previous: ?*CoreDirectorData,

    // pub fn contextSwitch(core_director_data: *CoreDirectorData) void {
    //     if (core_director_data.virtual_address_space) |virtual_address_space| {
    //         if (!virtual_address_space.options.mapped_page_tables) @panic("Page tables are not mapped before context switching");
    //         privileged.arch.paging.contextSwitch(virtual_address_space);
    //         context_switch_counter += 1;
    //     } else {
    //         @panic("VAS null");
    //     }
    //     // TODO: implement LDT
    // }
    //
    var context_switch_counter: usize = 0;
};

pub const CoreDirectorSharedGeneric = extern struct {
    disabled: u32,
    haswork: u32,
    udisp: VirtualAddress,
    lmp_delivered: u32,
    lmp_seen: u32,
    lmp_hint: VirtualAddress,
    dispatcher_run: VirtualAddress,
    dispatcher_lrpc: VirtualAddress,
    dispatcher_page_fault: VirtualAddress,
    dispatcher_page_fault_disabled: VirtualAddress,
    dispatcher_trap: VirtualAddress,
    // TODO: time
    systime_frequency: u64,
    core_id: u32,

    pub fn getDisabledSaveArea(core_director_shared_generic: *CoreDirectorSharedGeneric) *arch.Registers {
        const core_director_shared_arch = @fieldParentPtr(arch.CoreDirectorShared, "base", core_director_shared_generic);
        return &core_director_shared_arch.disabled_save_area;
    }
};

fn capabilityNodeSlice(node: *Capabilities.CTE) *[1]Capabilities.CTE {
    return @ptrCast(*[1]Capabilities.CTE, node);
}

pub inline fn spawnInitModule(spawn: *SpawnState) !*CoreDirectorData {
    _ = spawn;
    assert(current_supervisor != null);
    const root_capability_node = &current_supervisor.?.init_root_capability_node;
    MappingDatabase.init(current_supervisor.?) catch @panic("Unable to initialize mapping database");
    current_supervisor.?.is_valid = true;

    const root_capability_node_slice = capabilityNodeSlice(root_capability_node);
    Capabilities.new(.l1cnode, (page_allocator.allocate(Capabilities.Size.l2cnode, 0x1000) catch @panic("capability allocation failed")).address, Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, core_id, root_capability_node_slice) catch @panic("Cannot create capability root node");

    if (bsp) {
        const bsp_kernel_control_block_capability = Capabilities.Capability{
            .object = .{
                .kernel_control_block = current_supervisor.?,
            },
            .rights = Capabilities.Rights.all,
            .type = .kernel_control_block,
        };
        const bsp_kernel_control_block = Capabilities.locateSlot(root_capability_node.getNode(), @enumToInt(Capabilities.RootCNodeSlot.bsp_kernel_control_block));
        assert(bsp_kernel_control_block.capability.type == .null);
        bsp_kernel_control_block.capability = bsp_kernel_control_block_capability;
    }

    spawn_state.cnodes.task = Capabilities.locateSlot(root_capability_node.getNode(), @enumToInt(Capabilities.RootCNodeSlot.task));
    try Capabilities.new(.l2cnode, (try page_allocator.allocate(Capabilities.Size.l2cnode, lib.arch.valid_page_sizes[0])).address, Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, core_id, capabilityNodeSlice(spawn_state.cnodes.task orelse unreachable));

    spawn_state.cnodes.page = Capabilities.locateSlot(root_capability_node.getNode(), @enumToInt(Capabilities.RootCNodeSlot.page));
    try Capabilities.new(.l2cnode, (try page_allocator.allocate(Capabilities.Size.l2cnode, lib.arch.valid_page_sizes[0])).address, Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, core_id, capabilityNodeSlice(spawn_state.cnodes.page orelse unreachable));

    spawn_state.cnodes.base_page = Capabilities.locateSlot(root_capability_node.getNode(), @enumToInt(Capabilities.RootCNodeSlot.base_page));
    try Capabilities.new(.l2cnode, (try page_allocator.allocate(Capabilities.Size.l2cnode, lib.arch.valid_page_sizes[0])).address, Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, core_id, capabilityNodeSlice(spawn_state.cnodes.base_page orelse unreachable));

    spawn_state.cnodes.early_cnode = Capabilities.locateSlot(root_capability_node.getNode(), @enumToInt(Capabilities.RootCNodeSlot.early_cnode));
    try Capabilities.new(.l2cnode, (try page_allocator.allocate(Capabilities.Size.l2cnode, lib.arch.valid_page_sizes[0])).address, Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, core_id, capabilityNodeSlice(spawn_state.cnodes.early_cnode orelse unreachable));

    spawn_state.cnodes.super = Capabilities.locateSlot(root_capability_node.getNode(), @enumToInt(Capabilities.RootCNodeSlot.super));
    try Capabilities.new(.l2cnode, (try page_allocator.allocate(Capabilities.Size.l2cnode, lib.arch.valid_page_sizes[0])).address, Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, core_id, capabilityNodeSlice(spawn_state.cnodes.super orelse unreachable));

    spawn_state.cnodes.slot_alloc0 = Capabilities.locateSlot(root_capability_node.getNode(), @enumToInt(Capabilities.RootCNodeSlot.slot_alloc0));
    try Capabilities.new(.l2cnode, (try page_allocator.allocate(4 * Capabilities.Size.l2cnode, lib.arch.valid_page_sizes[0])).address, 4 * Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, core_id, capabilityNodeSlice(spawn_state.cnodes.slot_alloc0 orelse unreachable));

    spawn_state.cnodes.seg = Capabilities.locateSlot(root_capability_node.getNode(), @enumToInt(Capabilities.RootCNodeSlot.seg));
    try Capabilities.new(.l2cnode, (try page_allocator.allocate(Capabilities.Size.l2cnode, lib.arch.valid_page_sizes[0])).address, Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, core_id, capabilityNodeSlice(spawn_state.cnodes.seg orelse unreachable));

    spawn_state.cnodes.physical_address = Capabilities.locateSlot(root_capability_node.getNode(), @enumToInt(Capabilities.RootCNodeSlot.physical_address));
    try Capabilities.new(.l2cnode, (try page_allocator.allocate(Capabilities.Size.l2cnode, lib.arch.valid_page_sizes[0])).address, Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, core_id, capabilityNodeSlice(spawn_state.cnodes.physical_address orelse unreachable));

    // TODO @ArchIndependent
    if (bsp) {
        spawn_state.cnodes.module = Capabilities.locateSlot(root_capability_node.getNode(), @enumToInt(Capabilities.RootCNodeSlot.module));
        try Capabilities.new(.l2cnode, (try page_allocator.allocate(Capabilities.Size.l2cnode, lib.arch.valid_page_sizes[0])).address, Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, core_id, capabilityNodeSlice(spawn_state.cnodes.module orelse unreachable));
    }

    const init_dcb_cte = Capabilities.locateSlot(spawn_state.cnodes.task.?.getNode(), @enumToInt(Capabilities.TaskCNodeSlot.dispatcher));
    try Capabilities.new(.dispatcher, (try page_allocator.allocate(Capabilities.Size.dispatcher, lib.arch.valid_page_sizes[0])).address, Capabilities.Size.dispatcher, 0, core_id, capabilityNodeSlice(init_dcb_cte));

    const init_dispatcher_data = init_dcb_cte.capability.object.dispatcher.current;

    try root_capability_node.copy_to_cnode(spawn_state.cnodes.task orelse unreachable, @enumToInt(Capabilities.TaskCNodeSlot.root), false, 0, 0);

    const init_dispatcher_frame_cte = Capabilities.locateSlot(spawn_state.cnodes.task.?.getNode(), @enumToInt(Capabilities.TaskCNodeSlot.dispatcher_frame));
    try Capabilities.new(.frame, (try page_allocator.allocate(Capabilities.dispatcher_frame_size, Capabilities.dispatcher_frame_size)).address, Capabilities.dispatcher_frame_size, Capabilities.dispatcher_frame_size, core_id, capabilityNodeSlice(init_dispatcher_frame_cte));

    try init_dispatcher_frame_cte.copy_to_cte(&init_dispatcher_data.dispatcher_cte, false, 0, 0);

    const init_args_cte = Capabilities.locateSlot(spawn_state.cnodes.task.?.getNode(), @enumToInt(Capabilities.TaskCNodeSlot.args_space));
    try Capabilities.new(.frame, (try page_allocator.allocate(Capabilities.args_size, Capabilities.args_size)).address, Capabilities.args_size, Capabilities.args_size, core_id, capabilityNodeSlice(init_args_cte));
    spawn_state.argument_page_address = init_args_cte.capability.object.frame.base;

    // TODO @ArchIndependent
    if (bsp) {
        //log.warn("todo: bootloader information", .{});
    }

    const kernel_cap_cte = Capabilities.locateSlot(spawn_state.cnodes.task.?.getNode(), @enumToInt(Capabilities.TaskCNodeSlot.kernel_cap));
    try Capabilities.new(.kernel, .null, 0, 0, core_id, capabilityNodeSlice(kernel_cap_cte));

    const performance_monitor_cap_cte = Capabilities.locateSlot(spawn_state.cnodes.task.?.getNode(), @enumToInt(Capabilities.TaskCNodeSlot.performance_monitor));
    try Capabilities.new(.performance_monitor, .null, 0, 0, core_id, capabilityNodeSlice(performance_monitor_cap_cte));

    const irq_table_cap_cte = Capabilities.locateSlot(spawn_state.cnodes.task.?.getNode(), @enumToInt(Capabilities.TaskCNodeSlot.irq));
    try Capabilities.new(.irq_table, .null, 0, 0, core_id, capabilityNodeSlice(irq_table_cap_cte));

    const ipi_cap_cte = Capabilities.locateSlot(spawn_state.cnodes.task.?.getNode(), @enumToInt(Capabilities.TaskCNodeSlot.ipi));
    try Capabilities.new(.ipi, .null, 0, 0, core_id, capabilityNodeSlice(ipi_cap_cte));

    const process_manager_cap_cte = Capabilities.locateSlot(spawn_state.cnodes.task.?.getNode(), @enumToInt(Capabilities.TaskCNodeSlot.process_manager));
    try Capabilities.new(.process_manager, .null, 0, 0, core_id, capabilityNodeSlice(process_manager_cap_cte));

    const io_cte = Capabilities.locateSlot(spawn_state.cnodes.task.?.getNode(), @enumToInt(Capabilities.TaskCNodeSlot.io));
    try Capabilities.new(.io, .null, 0, 0, core_id, capabilityNodeSlice(io_cte));

    const init_handle = init_dispatcher_frame_cte.capability.object.frame.base.toHigherHalfVirtualAddress();
    //const &init_handle.access(*arch.Dispatcher).base;
    const init_core_director = init_handle.access(*CoreDirectorSharedGeneric);
    init_core_director.disabled = @boolToInt(true);
    init_core_director.core_id = core_id;

    try root_capability_node.copy_to_cte(&init_dispatcher_data.cspace, false, 0, 0);

    init_dispatcher_data.shared = init_handle.access(*CoreDirectorSharedGeneric);
    init_dispatcher_data.disabled = true;
    Scheduler.make_runnable(init_dispatcher_data);

    const base_page_cn_cte = Capabilities.locateSlot(spawn_state.cnodes.base_page.?.getNode(), 0);
    try Capabilities.new(.ram, (try page_allocator.allocate(Capabilities.l2_cnode_slots * lib.arch.valid_page_sizes[0], lib.arch.valid_page_sizes[0])).address, Capabilities.l2_cnode_slots * lib.arch.valid_page_sizes[0], lib.arch.valid_page_sizes[0], core_id, capabilityNodeSlice(base_page_cn_cte));

    const early_cnode_cn_cte = Capabilities.locateSlot(spawn_state.cnodes.early_cnode.?.getNode(), 0);
    try Capabilities.new(.ram, (try page_allocator.allocate(Capabilities.early_cnode_allocated_slots * Capabilities.Size.l2cnode, lib.arch.valid_page_sizes[0])).address, Capabilities.early_cnode_allocated_slots * Capabilities.Size.l2cnode, Capabilities.Size.l2cnode, core_id, capabilityNodeSlice(early_cnode_cn_cte));

    return init_dispatcher_data;
}
