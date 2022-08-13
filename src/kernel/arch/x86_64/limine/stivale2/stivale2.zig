const kernel = @import("root");
const common = @import("../../../../../common.zig");
const stivale = @import("header.zig");
const context = @import("context");

const log = common.log.scoped(.stivale);
const TODO = common.TODO;
const Allocator = common.Allocator;
const VirtualAddress = common.VirtualAddress;
const VirtualAddressSpace = common.VirtualAddressSpace;
const VirtualMemoryRegion = common.VirtualMemoryRegion;
const PhysicalAddress = common.PhysicalAddress;
const PhysicalAddressSpace = common.PhysicalAddressSpace;
const PhysicalMemoryRegion = common.PhysicalMemoryRegion;
const VirtualMemoryRegionWithPermissions = common.VirtualMemoryRegion;
const Thread = common.Thread;
const CPU = common.arch.CPU;
const SegmentedList = common.SegmentedList;

pub const Struct = stivale.Struct;

pub const Error = error{
    memory_map,
    higher_half_direct_map,
    kernel_file,
    pmrs,
    rsdp,
    smp,
};
const BootloaderInformation = struct {
    kernel_sections_in_memory: []VirtualMemoryRegion,
    kernel_file: common.File,
};

pub fn process_bootloader_information(virtual_address_space: *VirtualAddressSpace, stivale2_struct: *Struct, bootstrap_context: *common.BootstrapContext, scheduler: *common.Scheduler) Error!BootloaderInformation {
    common.runtime_assert(@src(), virtual_address_space.lock.status == 0);
    const kernel_sections_in_memory = try process_pmrs(virtual_address_space, stivale2_struct);
    log.debug("Processed sections in memory", .{});
    const kernel_file = try process_kernel_file(virtual_address_space, stivale2_struct);
    log.debug("Processed kernel file in memory", .{});
    try process_smp(virtual_address_space, stivale2_struct, bootstrap_context, scheduler);
    log.debug("Processed SMP info", .{});

    return BootloaderInformation{
        .kernel_sections_in_memory = kernel_sections_in_memory,
        .kernel_file = kernel_file,
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
    const page_size = context.page_size;
    const memory_map_struct = find(Struct.MemoryMap, stivale2_struct) orelse return Error.memory_map;
    const memory_map_entries = memory_map_struct.memmap()[0..memory_map_struct.entry_count];
    var result = PhysicalAddressSpace.new();

    // First, it is required to find a spot in memory big enough to host all the memory map entries in a architecture-independent and bootloader-independent way. This is the host entry
    const host_entry = blk: {
        for (memory_map_entries) |*entry| {
            if (entry.type == .usable) {
                const bitset = PhysicalAddressSpace.MapEntry.get_bitset_from_address_and_size(PhysicalAddress.new(entry.address), entry.size, page_size);
                const bitset_size = bitset.len * @sizeOf(PhysicalAddressSpace.MapEntry.BitsetBaseType);
                // INFO: this is separated since the bitset needs to be in a different page than the memory map
                const bitset_page_count = common.bytes_to_pages(bitset_size, context.page_size, .can_be_not_exact);
                // Allocate a bit more memory than needed just in case
                const memory_map_allocation_size = memory_map_struct.entry_count * @sizeOf(PhysicalAddressSpace.MapEntry);
                const memory_map_page_count = common.bytes_to_pages(memory_map_allocation_size, context.page_size, .can_be_not_exact);
                const total_allocated_page_count = bitset_page_count + memory_map_page_count;
                const total_allocation_size = context.page_size * total_allocated_page_count;
                common.runtime_assert(@src(), entry.size > total_allocation_size);
                result.usable = @intToPtr([*]PhysicalAddressSpace.MapEntry, entry.address + common.align_forward(bitset_size, context.page_size))[0..1];
                var block = &result.usable[0];
                block.* = PhysicalAddressSpace.MapEntry{
                    .descriptor = PhysicalMemoryRegion{
                        .address = PhysicalAddress.new(entry.address),
                        .size = entry.size,
                    },
                    .allocated_size = total_allocation_size,
                    .type = .usable,
                };

                block.setup_bitset(context.page_size);

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

            const bitset = result_entry.get_bitset_extended(page_size);
            const bitset_size = bitset.len * @sizeOf(PhysicalAddressSpace.MapEntry.BitsetBaseType);
            result_entry.allocated_size = common.align_forward(bitset_size, context.page_size);
            result_entry.setup_bitset(context.page_size);
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

    common.runtime_assert(@src(), result.kernel_and_modules.len == 1);

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

    common.runtime_assert(@src(), virtual_address_space.lock.status == 0);
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
pub fn process_kernel_file(virtual_address_space: *VirtualAddressSpace, stivale2_struct: *Struct) Error!common.File {
    const kernel_file = find(stivale.Struct.KernelFileV2, stivale2_struct) orelse return Error.kernel_file;
    const file_address = PhysicalAddress.new(kernel_file.kernel_file);
    const file_size = kernel_file.kernel_size;
    // TODO: consider alignment?
    log.debug("allocation about to happen", .{});
    const dst = virtual_address_space.heap.allocator.alloc(u8, file_size) catch return Error.kernel_file;
    log.debug("allocation did happen", .{});
    const src = file_address.access_kernel([*]u8)[0..file_size];
    log.debug("Copying kernel file to (0x{x}, 0x{x})", .{ @ptrToInt(dst.ptr), @ptrToInt(dst.ptr) + dst.len });
    common.copy(u8, dst, src);
    return common.File{
        .address = VirtualAddress.new(@ptrToInt(dst.ptr)),
        .size = file_size,
    };
}

pub fn process_rsdp(stivale2_struct: *Struct) Error!PhysicalAddress {
    const rsdp_struct = find(stivale.Struct.RSDP, stivale2_struct) orelse return Error.rsdp;
    const rsdp = rsdp_struct.rsdp;
    log.debug("RSDP struct: 0x{x}", .{rsdp});
    const rsdp_address = PhysicalAddress.new(rsdp);
    return rsdp_address;
}

fn smp_entry(smp_info: *Struct.SMP.Info) callconv(.C) noreturn {
    const initialization_context = @intToPtr(*CPUInitializationContext, smp_info.extra_argument);
    const virtual_address_space = initialization_context.kernel_virtual_address_space;
    const scheduler = initialization_context.scheduler;
    const cpu_index = smp_info.processor_id;
    // Current thread is already set in the process_smp function
    common.arch.preset_thread_pointer(cpu_index);
    virtual_address_space.make_current();
    common.arch.cpu_start(virtual_address_space);
    log.debug("CPU started", .{});

    _ = @atomicRmw(u64, &scheduler.initialized_ap_cpu_count, .Add, 1, .AcqRel);
    while (true) {
        asm volatile ("pause" ::: "memory");
    }
}

const CPUInitializationContext = struct {
    kernel_virtual_address_space: *VirtualAddressSpace,
    scheduler: *common.Scheduler,
};

var cpu_initialization_context: CPUInitializationContext = undefined;

pub fn process_smp(virtual_address_space: *VirtualAddressSpace, stivale2_struct: *Struct, bootstrap_context: *common.BootstrapContext, scheduler: *common.Scheduler) Error!void {
    common.runtime_assert(@src(), virtual_address_space.privilege_level == .kernel);
    cpu_initialization_context = CPUInitializationContext{
        .kernel_virtual_address_space = virtual_address_space,
        .scheduler = scheduler,
    };

    const smp_struct = find(stivale.Struct.SMP, stivale2_struct) orelse return Error.smp;
    log.debug("SMP struct: {}", .{smp_struct});

    const cpu_count = smp_struct.cpu_count;
    const thread_count = cpu_count;
    scheduler.cpus = virtual_address_space.heap.allocator.alloc(CPU, cpu_count) catch return Error.smp;
    const smps = smp_struct.smp_info()[0..cpu_count];
    common.runtime_assert(@src(), smps[0].lapic_id == smp_struct.bsp_lapic_id);
    scheduler.cpus[0] = bootstrap_context.cpu;
    scheduler.cpus[0].is_bootstrap = true;
    const bsp_thread = scheduler.thread_buffer.add_one(virtual_address_space.heap.allocator) catch @panic("wtf");
    bsp_thread.all_item = Thread.ListItem.new(bsp_thread);
    bsp_thread.queue_item = Thread.ListItem.new(bsp_thread);
    scheduler.all_threads.append(&bsp_thread.all_item, bsp_thread) catch @panic("wtF");
    bsp_thread.context = &bootstrap_context.context;
    bsp_thread.state = .active;
    bsp_thread.cpu = &scheduler.cpus[0];
    common.arch.set_current_thread(bsp_thread);
    common.arch.allocate_and_setup_thread_pointers(virtual_address_space, scheduler);

    const entry_point = @ptrToInt(smp_entry);
    const ap_cpu_count = scheduler.cpus.len - 1;
    const ap_threads = scheduler.bulk_spawn_same_thread(virtual_address_space, .kernel, ap_cpu_count, entry_point);
    common.runtime_assert(@src(), scheduler.all_threads.count == ap_threads.len + 1);
    common.runtime_assert(@src(), scheduler.all_threads.count < Thread.Buffer.Bucket.size);
    const all_threads = scheduler.thread_buffer.first.?.data[0..thread_count];
    common.runtime_assert(@src(), &all_threads[0] == bsp_thread);

    for (smps) |smp, index| {
        const cpu = &scheduler.cpus[index];
        const thread = &all_threads[index];
        cpu.lapic.id = smp.lapic_id;
        cpu.id = smp.processor_id;
        thread.cpu = cpu;
        thread.executing = true;
    }

    // TODO: don't hardcode stack size
    common.arch.bootstrap_stacks(scheduler.cpus, virtual_address_space, 0x10000);
    common.runtime_assert(@src(), common.cpu.arch == .x86_64);
    common.arch.x86_64.map_lapic(virtual_address_space);

    scheduler.lock.acquire();
    for (smps[1..]) |*smp, index| {
        const ap_thread = &ap_threads[index];
        scheduler.active_threads.remove(&ap_thread.queue_item);
        const stack_pointer = ap_thread.context.get_stack_pointer();
        smp.extra_argument = @ptrToInt(&cpu_initialization_context);
        smp.target_stack = stack_pointer;
        smp.goto_address = entry_point;
    }
    common.runtime_assert(@src(), scheduler.active_threads.count == 0);

    // @ZigBug if this is written with atomic operations, it gets optimized out by the compiler or LLVM
    //while (@atomicLoad(u64, &scheduler.initalizated_ap_cpu_count, .Acquire) < ap_cpu_count) {}
    while (@as(*volatile u64, &scheduler.initialized_ap_cpu_count).* < ap_cpu_count) {}
    log.debug("Initialized all cores", .{});
    scheduler.lock.release();
}
