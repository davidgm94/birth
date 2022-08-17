const std = @import("../../../../../common/std.zig");

const common = @import("../../../../common.zig");
const Context = @import("../../context.zig");
const context_switch = @import("../../context_switch.zig");
const CPU = @import("../../cpu.zig");
const crash = @import("../../../../crash.zig");
const kernel = @import("../../../../kernel.zig");
const stivale = @import("header.zig");
const x86_64 = @import("../../common.zig");
const VirtualAddress = @import("../../../../virtual_address.zig");
const VirtualAddressSpace = @import("../../../../virtual_address_space.zig");
const VirtualMemoryRegion = @import("../../../../virtual_memory_region.zig");
const PhysicalAddress = @import("../../../../physical_address.zig");
const PhysicalAddressSpace = @import("../../../../physical_address_space.zig");
const PhysicalMemoryRegion = @import("../../../../physical_memory_region.zig");
const Scheduler = @import("../../../../scheduler.zig");
const SegmentedList = @import("../../../../../common/list.zig").SegmentedList;
const Thread = @import("../../../../thread.zig");
const TLS = @import("../../tls.zig");

const FileInMemory = common.FileInMemory;
const page_size = x86_64.page_size;
const log = std.log.scoped(.stivale);
const TODO = crash.TODO;
const Allocator = std.Allocator;

pub const Struct = stivale.Struct;

pub const Error = error{
    memory_map,
    higher_half_direct_map,
    kernel_file,
    pmrs,
    rsdp,
    smp,
    framebuffer,
};

const BootloaderInformation = struct {
    kernel_sections_in_memory: []VirtualMemoryRegion,
    kernel_file: FileInMemory,
    framebuffer: Framebuffer,
};

const Framebuffer = struct {};

pub const BootstrapContext = struct {
    cpu: CPU,
    thread: Thread,
    context: Context,

    pub fn preinit_bsp(bootstrap_context: *BootstrapContext, scheduler: *Scheduler, virtual_address_space: *VirtualAddressSpace) void {
        bootstrap_context.cpu.id = 0;
        TLS.preset_bsp(scheduler, &bootstrap_context.thread, &bootstrap_context.cpu);
        bootstrap_context.thread.context = &bootstrap_context.context;
        bootstrap_context.thread.address_space = virtual_address_space;

        // @ZigBug: @ptrCast here crashes the compiler
        scheduler.cpus = @intToPtr([*]CPU, @ptrToInt(&bootstrap_context.cpu))[0..1];
    }
};

pub fn process_bootloader_information(virtual_address_space: *VirtualAddressSpace, stivale2_struct: *Struct, bootstrap_context: *BootstrapContext, scheduler: *Scheduler) Error!BootloaderInformation {
    std.assert(virtual_address_space.lock.status == 0);
    const kernel_sections_in_memory = try process_pmrs(virtual_address_space, stivale2_struct);
    log.debug("Processed sections in memory", .{});
    const kernel_file = try process_kernel_file(virtual_address_space, stivale2_struct);
    log.debug("Processed kernel file in memory", .{});
    const framebuffer = try process_framebuffer(virtual_address_space, stivale2_struct);
    log.debug("Processed framebuffer", .{});
    try process_smp(virtual_address_space, stivale2_struct, bootstrap_context, scheduler);
    log.debug("Processed SMP info", .{});

    return BootloaderInformation{
        .kernel_sections_in_memory = kernel_sections_in_memory,
        .kernel_file = kernel_file,
        .framebuffer = framebuffer,
    };
}

pub fn find(comptime StructT: type, stivale2_struct: *Struct) ?*align(1) StructT {
    var tag_opt = get_tag_from_physical(PhysicalAddress.new(stivale2_struct.tags));

    while (tag_opt) |tag| {
        if (tag.identifier == StructT.id) {
            return @ptrCast(*align(1) StructT, tag);
        }

        tag_opt = get_tag_from_physical(PhysicalAddress.new(tag.next));
    }

    return null;
}

fn get_tag_from_physical(physical_address: PhysicalAddress) ?*align(1) stivale.Tag {
    return physical_address.access_kernel(?*align(1) stivale.Tag);
}

pub fn process_memory_map(stivale2_struct: *Struct) Error!PhysicalAddressSpace {
    const memory_map_struct = find(Struct.MemoryMap, stivale2_struct) orelse return Error.memory_map;
    const memory_map_entries = memory_map_struct.memmap()[0..memory_map_struct.entry_count];
    var result = PhysicalAddressSpace{};

    // First, it is required to find a spot in memory big enough to host all the memory map entries in a architecture-independent and bootloader-independent way. This is the host entry
    const host_entry = blk: {
        for (memory_map_entries) |*entry| {
            if (entry.type == .usable) {
                const bitset = PhysicalAddressSpace.MapEntry.get_bitset_from_address_and_size(PhysicalAddress.new(entry.address), entry.size);
                const bitset_size = bitset.len * @sizeOf(PhysicalAddressSpace.MapEntry.BitsetBaseType);
                // INFO: this is separated since the bitset needs to be in a different page than the memory map
                const bitset_page_count = std.bytes_to_pages(bitset_size, page_size, .can_be_not_exact);
                // Allocate a bit more memory than needed just in case
                const memory_map_allocation_size = memory_map_struct.entry_count * @sizeOf(PhysicalAddressSpace.MapEntry);
                const memory_map_page_count = std.bytes_to_pages(memory_map_allocation_size, page_size, .can_be_not_exact);
                const total_allocated_page_count = bitset_page_count + memory_map_page_count;
                const total_allocation_size = page_size * total_allocated_page_count;
                std.assert(entry.size > total_allocation_size);
                result.usable = @intToPtr([*]PhysicalAddressSpace.MapEntry, entry.address + std.align_forward(bitset_size, page_size))[0..1];
                var block = &result.usable[0];
                block.* = PhysicalAddressSpace.MapEntry{
                    .descriptor = PhysicalMemoryRegion{
                        .address = PhysicalAddress.new(entry.address),
                        .size = entry.size,
                    },
                    .allocated_size = total_allocation_size,
                    .type = .usable,
                };

                block.setup_bitset();

                break :blk block;
            }
        }

        @panic("There is no memory map entry big enough to store the memory map entries");
    };

    // The counter starts with one because we have already filled the memory map with the host entry
    for (memory_map_entries) |*entry| {
        if (entry.type == .usable) {
            if (entry.address == host_entry.descriptor.address.value) continue;

            const index = result.usable.len;
            result.usable.len += 1;
            var result_entry = &result.usable[index];
            result_entry.* = PhysicalAddressSpace.MapEntry{
                .descriptor = PhysicalMemoryRegion{
                    .address = PhysicalAddress.new(entry.address),
                    .size = entry.size,
                },
                .allocated_size = 0,
                .type = .usable,
            };

            const bitset = result_entry.get_bitset_extended();
            const bitset_size = bitset.len * @sizeOf(PhysicalAddressSpace.MapEntry.BitsetBaseType);
            result_entry.allocated_size = std.align_forward(bitset_size, page_size);
            result_entry.setup_bitset();
        }
    }

    result.reclaimable.ptr = @intToPtr(@TypeOf(result.reclaimable.ptr), @ptrToInt(result.usable.ptr) + (@sizeOf(PhysicalAddressSpace.MapEntry) * result.usable.len));

    for (memory_map_entries) |*entry| {
        if (entry.type == .bootloader_reclaimable) {
            const index = result.reclaimable.len;
            result.reclaimable.len += 1;
            var result_entry = &result.reclaimable[index];
            result_entry.* = PhysicalAddressSpace.MapEntry{
                .descriptor = PhysicalMemoryRegion{
                    .address = PhysicalAddress.new(entry.address),
                    .size = entry.size,
                },
                .allocated_size = 0,
                .type = .reclaimable,
            };

            // Don't use the bitset here because it would imply using memory that may not be usable at the moment of writing the bitset to this region
        }
    }

    result.framebuffer.ptr = @intToPtr(@TypeOf(result.framebuffer.ptr), @ptrToInt(result.reclaimable.ptr) + (@sizeOf(PhysicalAddressSpace.MapEntry) * result.reclaimable.len));

    for (memory_map_entries) |*entry| {
        if (entry.type == .framebuffer) {
            const index = result.framebuffer.len;
            result.framebuffer.len += 1;
            var result_entry = &result.framebuffer[index];
            result_entry.* = PhysicalMemoryRegion{
                .address = PhysicalAddress.new(entry.address),
                .size = entry.size,
            };

            // Don't use the bitset here because it would imply using memory that may not be usable at the moment of writing the bitset to this region
        }
    }

    result.kernel_and_modules.ptr = @intToPtr(@TypeOf(result.kernel_and_modules.ptr), @ptrToInt(result.framebuffer.ptr) + (@sizeOf(PhysicalMemoryRegion) * result.framebuffer.len));

    for (memory_map_entries) |*entry| {
        if (entry.type == .kernel_and_modules) {
            const index = result.kernel_and_modules.len;
            result.kernel_and_modules.len += 1;
            var result_entry = &result.kernel_and_modules[index];
            result_entry.* = PhysicalMemoryRegion{
                .address = PhysicalAddress.new(entry.address),
                .size = entry.size,
            };

            // Don't use the bitset here because it would imply using memory that may not be usable at the moment of writing the bitset to this region
        }
    }

    std.assert(result.kernel_and_modules.len == 1);

    result.reserved.ptr = @intToPtr(@TypeOf(result.reserved.ptr), @ptrToInt(result.kernel_and_modules.ptr) + (@sizeOf(PhysicalMemoryRegion) * result.kernel_and_modules.len));

    for (memory_map_entries) |*entry| {
        if (entry.type == .reserved) {
            const index = result.reserved.len;
            result.reserved.len += 1;
            var result_entry = &result.reserved[index];
            result_entry.* = PhysicalMemoryRegion{
                .address = PhysicalAddress.new(entry.address),
                .size = entry.size,
            };

            // Don't use the bitset here because it would imply using memory that may not be usable at the moment of writing the bitset to this region
        }
    }

    log.debug("Memory map initialized", .{});

    return result;
}

pub fn process_higher_half_direct_map(stivale2_struct: *Struct) Error!u64 {
    const hhdm_struct = find(Struct.HHDM, stivale2_struct) orelse return Error.higher_half_direct_map;
    log.debug("HHDM: 0x{x}", .{hhdm_struct.addr});
    // INFO: this is just checking the address is valid
    const hhdm = VirtualAddress.new(hhdm_struct.addr);
    return hhdm.value;
}

pub fn process_pmrs(virtual_address_space: *VirtualAddressSpace, stivale2_struct: *Struct) Error![]VirtualMemoryRegion {
    const pmrs_struct = find(stivale.Struct.PMRs, stivale2_struct) orelse return Error.pmrs;
    log.debug("PMRS struct: 0x{x}", .{@ptrToInt(pmrs_struct)});
    const pmrs = pmrs_struct.pmrs()[0..pmrs_struct.entry_count];
    if (pmrs.len == 0) return Error.pmrs;

    std.assert(virtual_address_space.lock.status == 0);
    const kernel_sections = virtual_address_space.heap.allocator.alloc(VirtualMemoryRegion, pmrs.len) catch return Error.pmrs;

    for (pmrs) |pmr, i| {
        const kernel_section = &kernel_sections[i];
        kernel_section.address = VirtualAddress.new(pmr.address);
        kernel_section.size = pmr.size;
        //const permissions = pmr.permissions;
        //kernel_section.read = permissions & (1 << stivale.Struct.PMRs.PMR.readable) != 0;
        //kernel_section.write = permissions & (1 << stivale.Struct.PMRs.PMR.writable) != 0;
        //kernel_section.execute = permissions & (1 << stivale.Struct.PMRs.PMR.executable) != 0;
    }

    return kernel_sections;
}

pub fn get_pmrs(stivale2_struct: *Struct) []Struct.PMRs.PMR {
    const pmrs_struct = find(stivale.Struct.PMRs, stivale2_struct) orelse unreachable;
    const pmrs = pmrs_struct.pmrs()[0..pmrs_struct.entry_count];
    return pmrs;
}

/// This procedure copies the kernel file in a region which is usable and whose allocationcan be registered in the physical allocator bitset
pub fn process_kernel_file(virtual_address_space: *VirtualAddressSpace, stivale2_struct: *Struct) Error!FileInMemory {
    const kernel_file = find(stivale.Struct.KernelFileV2, stivale2_struct) orelse return Error.kernel_file;
    const file_address = PhysicalAddress.new(kernel_file.kernel_file);
    const file_size = kernel_file.kernel_size;
    // TODO: consider alignment?
    log.debug("allocation about to happen", .{});
    const dst = virtual_address_space.heap.allocator.alloc(u8, file_size) catch return Error.kernel_file;
    log.debug("allocation did happen", .{});
    const src = file_address.access_kernel([*]u8)[0..file_size];
    log.debug("Copying kernel file to (0x{x}, 0x{x})", .{ @ptrToInt(dst.ptr), @ptrToInt(dst.ptr) + dst.len });
    std.copy(u8, dst, src);
    return FileInMemory{
        .address = VirtualAddress.new(@ptrToInt(dst.ptr)),
        .size = file_size,
    };
}

pub fn process_rsdp(stivale2_struct: *Struct) Error!u64 {
    const rsdp_struct = find(stivale.Struct.RSDP, stivale2_struct) orelse return Error.rsdp;
    const rsdp = rsdp_struct.rsdp;
    log.debug("RSDP struct: 0x{x}", .{rsdp});
    return rsdp;
}

pub fn process_framebuffer(virtual_address_space: *VirtualAddressSpace, stivale2_struct: *Struct) Error!Framebuffer {
    _ = virtual_address_space;
    const framebuffer = find(stivale.Struct.Framebuffer, stivale2_struct) orelse return Error.framebuffer;
    log.debug("Framebuffer: {}", .{framebuffer});
    TODO();
    return Framebuffer{};
}

fn smp_entry(smp_info: *Struct.SMP.Info) callconv(.C) noreturn {
    const initialization_context = @intToPtr(*CPUInitializationContext, smp_info.extra_argument);
    const virtual_address_space = initialization_context.kernel_virtual_address_space;
    const scheduler = initialization_context.scheduler;
    const cpu_index = smp_info.processor_id;
    // Current thread is already set in the process_smp function
    TLS.preset(scheduler, &scheduler.cpus[cpu_index]);
    virtual_address_space.make_current();
    const current_thread = TLS.get_current();
    const cpu = current_thread.cpu orelse @panic("cpu");
    cpu.start(scheduler, virtual_address_space);
    log.debug("CPU started", .{});

    while (!cpu.ready) {
        cpu.lapic.next_timer(10);
        asm volatile (
            \\sti
            \\pause
            \\hlt
        );
    }

    log.debug("cpu is now ready", .{});
    cpu.make_thread_idle();
}

const CPUInitializationContext = struct {
    kernel_virtual_address_space: *VirtualAddressSpace,
    scheduler: *Scheduler,
};

var cpu_initialization_context: CPUInitializationContext = undefined;
var foo: Thread = undefined;
var foo2: Context = undefined;

pub fn process_smp(virtual_address_space: *VirtualAddressSpace, stivale2_struct: *Struct, bootstrap_context: *BootstrapContext, scheduler: *Scheduler) Error!void {
    std.assert(virtual_address_space.privilege_level == .kernel);
    cpu_initialization_context = CPUInitializationContext{
        .kernel_virtual_address_space = virtual_address_space,
        .scheduler = scheduler,
    };

    const smp_struct = find(stivale.Struct.SMP, stivale2_struct) orelse return Error.smp;
    log.debug("SMP struct: {}", .{smp_struct});

    const cpu_count = smp_struct.cpu_count;
    const smps = smp_struct.smp_info()[0..cpu_count];
    std.assert(smps[0].lapic_id == smp_struct.bsp_lapic_id);
    // @Allocation
    bootstrap_context.cpu.idle_thread = &foo;
    bootstrap_context.cpu.idle_thread.context = &foo2;
    bootstrap_context.cpu.idle_thread.context = &foo2;
    bootstrap_context.cpu.idle_thread.address_space = virtual_address_space;
    bootstrap_context.thread.context = &foo2;
    bootstrap_context.thread.address_space = virtual_address_space;

    scheduler.lock.acquire();

    const threads = scheduler.thread_buffer.add_many(virtual_address_space.heap.allocator, cpu_count) catch @panic("wtf");
    scheduler.current_threads = virtual_address_space.heap.allocator.alloc(*Thread, threads.len) catch @panic("wtf");
    const thread_stack_size = Scheduler.default_kernel_stack_size;
    const thread_bulk_stack_allocation_size = threads.len * thread_stack_size;
    const thread_stacks = virtual_address_space.allocate(thread_bulk_stack_allocation_size, null, .{ .write = true }) catch @panic("wtF");
    scheduler.cpus = virtual_address_space.heap.allocator.alloc(CPU, cpu_count) catch @panic("wtF");
    scheduler.cpus[0].id = smps[0].processor_id;
    // Dummy context
    TLS.preset(scheduler, &scheduler.cpus[0]);
    TLS.set_current(scheduler, &threads[0], &scheduler.cpus[0]);
    // Map LAPIC address on just one CPU (since it's global)
    CPU.map_lapic(virtual_address_space);

    // TODO: ignore BSP cpu when AP initialization?
    for (threads) |*thread, thread_i| {
        scheduler.current_threads[thread_i] = thread;
        const cpu = &scheduler.cpus[thread_i];
        const smp = &smps[thread_i];

        const stack_allocation_offset = thread_i * thread_stack_size;
        const kernel_stack_address = thread_stacks.offset(stack_allocation_offset);
        const thread_stack = Scheduler.ThreadStack{
            .kernel = .{ .address = kernel_stack_address, .size = thread_stack_size },
            .user = .{ .address = kernel_stack_address, .size = thread_stack_size },
        };

        const entry_point = @ptrToInt(smp_entry);
        scheduler.initialize_thread(thread, thread_i, virtual_address_space, .kernel, .idle, entry_point, thread_stack);
        thread.cpu = cpu;
        cpu.idle_thread = thread;
        cpu.id = smp.processor_id;
        cpu.lapic.id = smp.lapic_id;
        const stack_pointer = thread.context.get_stack_pointer();
        smp.extra_argument = @ptrToInt(&cpu_initialization_context);
        smp.target_stack = stack_pointer;
        smp.goto_address = entry_point;
    }

    // TODO: TSS

    // Update bsp CPU
    // TODO: maybe this is necessary?

    scheduler.lock.release();
}
