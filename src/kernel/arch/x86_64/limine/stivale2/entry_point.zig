const std = @import("../../../../../common/std.zig");

const CPUID = @import("../../../../../common/arch/x86_64/cpuid.zig");
const crash = @import("../../../../crash.zig");
const drivers = @import("../../drivers.zig");
const Graphics = @import("../../../../../drivers/graphics.zig");
const kernel = @import("../../../../kernel.zig");
const main = @import("../../../../main.zig").main;
const PhysicalAddress = @import("../../../../physical_address.zig");
const TLS = @import("../../tls.zig");
const Timer = @import("../../../../timer.zig");
const VAS = @import("../../vas.zig");
const VirtualAddressSpace = @import("../../../../virtual_address_space.zig");
const x86_64 = @import("../../../common.zig");
const default_logger = @import("../../../../log.zig");
const stivale_log = std.log.scoped(.Stivale);

//const std = @import("../../../../../common/std.zig");

const common = @import("../../../../common.zig");
const Context = @import("../../context.zig");
//const context_switch = @import("../../context_switch.zig");
const CPU = @import("../../cpu.zig");
//const crash = @import("../../../../crash.zig");
//const kernel = @import("../../../../kernel.zig");
const stivale = @import("header.zig");
//const x86_64 = @import("../../common.zig");
const VirtualAddress = @import("../../../../virtual_address.zig");
//const VirtualAddressSpace = @import("../../../../virtual_address_space.zig");
const VirtualMemoryRegion = @import("../../../../virtual_memory_region.zig");
//const PhysicalAddress = @import("../../../../physical_address.zig");
const PhysicalAddressSpace = @import("../../../../physical_address_space.zig");
const PhysicalMemoryRegion = @import("../../../../physical_memory_region.zig");
const Scheduler = @import("../../../../scheduler.zig");
//const SegmentedList = @import("../../../../../common/list.zig").SegmentedList;
const Thread = @import("../../../../thread.zig");
//const TLS = @import("../../tls.zig");

const FileInMemory = common.FileInMemory;
const Framebuffer = common.Framebuffer;
const page_size = x86_64.page_size;
//const log = std.log.scoped(.stivale);
const Struct = stivale.Struct;
const TODO = crash.TODO;
const Allocator = std.Allocator;

/// Define root.log_level to override the default
pub const log_level: std.log.Level = switch (std.build_mode) {
    .Debug => .debug,
    .ReleaseSafe => .debug,
    .ReleaseFast, .ReleaseSmall => .info,
};

pub fn log(comptime level: std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
    default_logger.lock.acquire();
    defer default_logger.lock.release();
    const current_thread = TLS.get_current();
    if (current_thread.cpu) |current_cpu| {
        const processor_id = current_cpu.id;
        default_logger.writer.print("[Kernel] [Core #{}] [Thread #{}] ", .{ processor_id, current_thread.id }) catch unreachable;
    } else {
        default_logger.writer.print("[Kernel] [WARNING: unknown core] [Thread #{}] ", .{current_thread.id}) catch unreachable;
    }
    default_logger.writer.writeAll(prefix) catch unreachable;
    default_logger.writer.print(format, args) catch unreachable;
    default_logger.writer.writeByte('\n') catch unreachable;
}

pub fn panic(message: []const u8, _: ?*std.StackTrace) noreturn {
    crash.panic_extended("{s}", .{message}, @returnAddress(), @frameAddress());
}

const BootloaderInformation = struct {
    kernel_sections_in_memory: []VirtualMemoryRegion,
    kernel_file: FileInMemory,
    framebuffer: Framebuffer,
};

pub const BootstrapContext = struct {
    cpu: CPU,
    thread: Thread,
    context: Context,
};

pub fn find(comptime StructT: type, stivale2_struct: *Struct) ?*align(1) StructT {
    var tag_opt = PhysicalAddress.new(stivale2_struct.tags).access_kernel(?*align(1) stivale.Tag);

    while (tag_opt) |tag| {
        if (tag.identifier == StructT.id) {
            return @ptrCast(*align(1) StructT, tag);
        }

        tag_opt = PhysicalAddress.new(tag.next).access_kernel(?*align(1) stivale.Tag);
    }

    return null;
}

const CPUInitializationContext = struct {
    kernel_virtual_address_space: *VirtualAddressSpace,
    scheduler: *Scheduler,
};

var cpu_initialization_context: CPUInitializationContext = undefined;
var foo: Thread = undefined;
var foo2: Context = undefined;

export fn kernel_smp_entry(smp_info: *Struct.SMP.Info) callconv(.C) noreturn {
    const logger = std.log.scoped(.SMPEntry);
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
    logger.debug("CPU started", .{});

    while (!cpu.ready) {
        cpu.lapic.next_timer(10);
        asm volatile (
            \\sti
            \\pause
            \\hlt
        );
    }

    logger.debug("cpu is now ready", .{});
    cpu.make_thread_idle();
}

pub export fn kernel_entry_point(stivale2_struct_address: u64) callconv(.C) noreturn {
    // Start a timer to count the CPU cycles the entry point function takes
    var entry_point_timer = Timer.Scoped(.EntryPoint).start();
    // Get maximum physical address information
    x86_64.max_physical_address_bit = CPUID.get_max_physical_address_bit();
    // Generate enough bootstraping structures to make some early stuff work
    kernel.virtual_address_space = VirtualAddressSpace.bootstrapping();
    var bootstrap_context = std.zeroes(BootstrapContext);
    {
        bootstrap_context.cpu.id = 0;
        TLS.preset_bsp(&kernel.scheduler, &bootstrap_context.thread, &bootstrap_context.cpu);
        bootstrap_context.thread.context = &bootstrap_context.context;
        bootstrap_context.thread.address_space = &kernel.virtual_address_space;

        // @ZigBug: @ptrCast here crashes the compiler
        kernel.scheduler.cpus = @intToPtr([*]CPU, @ptrToInt(&bootstrap_context.cpu))[0..1];
    }

    stivale_log.debug("Hello kernel!", .{});
    stivale_log.debug("Stivale2 address: 0x{x}", .{stivale2_struct_address});

    const stivale2_struct_physical_address = PhysicalAddress.new(stivale2_struct_address);
    var stivale2_struct = stivale2_struct_physical_address.access_kernel(*Struct);
    // This is just a cached version, not the global one (which is set after kernel address space initialization)
    const higher_half_direct_map = blk: {
        const hhdm_struct = find(Struct.HHDM, stivale2_struct) orelse @panic("Unable to find higher half direct map struct");
        stivale_log.debug("HHDM: 0x{x}", .{hhdm_struct.addr});
        if (hhdm_struct.addr == 0) {
            @panic("Received 0 as the higher half address");
        }

        break :blk hhdm_struct.addr;
    };

    x86_64.rsdp_physical_address = blk: {
        const rsdp_struct = find(stivale.Struct.RSDP, stivale2_struct) orelse @panic("Unable to find RSDP struct");
        const rsdp = rsdp_struct.rsdp;
        if (rsdp == 0) @panic("Received 0 as RSDP struct");
        stivale_log.debug("RSDP struct: 0x{x}", .{rsdp});
        break :blk rsdp;
    };

    kernel.physical_address_space = blk: {
        var timer = Timer.Scoped(.PhysicalAddressSpaceInitialization).start();
        defer timer.end_and_log();

        const memory_map_struct = find(Struct.MemoryMap, stivale2_struct) orelse @panic("Unable to find memory map struct");
        const memory_map_entries = memory_map_struct.memmap()[0..memory_map_struct.entry_count];
        var result = PhysicalAddressSpace{};

        // First, it is required to find a spot in memory big enough to host all the memory map entries in a architecture-independent and bootloader-independent way. This is the host entry
        const host_entry = host_entry_blk: {
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

                    break :host_entry_blk block;
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

        {
            const framebuffer_size = @sizeOf(PhysicalMemoryRegion) * result.framebuffer.len;
            const kernel_and_modules_slice_address = @ptrToInt(result.framebuffer.ptr) + framebuffer_size;
            result.kernel_and_modules.ptr = @intToPtr([*]PhysicalMemoryRegion, kernel_and_modules_slice_address);
        }

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

        {
            std.assert(result.kernel_and_modules.len == 1);
            const kernels_and_modules_size = @sizeOf(PhysicalMemoryRegion) * result.kernel_and_modules.len;
            const reserved_slice_address = @ptrToInt(result.kernel_and_modules.ptr) + kernels_and_modules_size;
            result.reserved.ptr = @intToPtr([*]PhysicalMemoryRegion, reserved_slice_address);
        }

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

        stivale_log.debug("Memory map initialized", .{});
        break :blk result;
    };

    // Init paging
    {
        var timer = Timer.Scoped(.VirtualAddressSpaceInitialization).start();
        defer timer.end_and_log();

        stivale_log.debug("About to dereference memory regions", .{});
        var new_virtual_address_space = VirtualAddressSpace{
            .arch = .{},
            .privilege_level = .kernel,
            .heap = .{},
            .lock = .{},
            .initialized = false,
        };
        // Using pointer initialization for virtual address space because it depends on the allocator pointer being stable
        VirtualAddressSpace.initialize_kernel_address_space(&new_virtual_address_space, &kernel.physical_address_space) orelse @panic("unable to initialize kernel address space");

        const stivale_pmrs_struct = find(Struct.PMRs, stivale2_struct) orelse @panic("Unable to find Stivale PMRs");
        const stivale_pmrs = stivale_pmrs_struct.pmrs()[0..stivale_pmrs_struct.entry_count];

        // Map the kernel and do some tests
        {
            var map_timer = Timer.Scoped(.KernelMap).start();
            defer map_timer.end_and_log();

            // TODO: better flags
            for (stivale_pmrs) |pmr| {
                const section_virtual_address = VirtualAddress.new(pmr.address);
                const kernel_section_virtual_region = VirtualMemoryRegion.new(section_virtual_address, pmr.size);
                const section_physical_address = kernel.virtual_address_space.translate_address(section_virtual_address) orelse @panic("address not translated");
                new_virtual_address_space.map_virtual_region(kernel_section_virtual_region, section_physical_address, .{
                    .execute = pmr.permissions & Struct.PMRs.PMR.executable != 0,
                    .write = true, //const writable = permissions & Stivale2.Struct.PMRs.PMR.writable != 0;
                });
            }
        }

        {
            var map_timer = Timer.Scoped(.UsableMap).start();
            defer map_timer.end_and_log();
            // TODO: better flags
            for (kernel.physical_address_space.usable) |region| {
                // This needs an specific offset since the kernel value "higher_half_direct_map" is not set yet. The to_higher_half_virtual_address() function depends on this value being set.
                // Therefore a manual set here is preferred as a tradeoff with a better runtime later when often calling the aforementioned function
                new_virtual_address_space.map_physical_region(region.descriptor, region.descriptor.address.to_virtual_address_with_offset(higher_half_direct_map), .{
                    .write = true,
                    .user = true,
                });
            }
        }

        {
            var map_timer = Timer.Scoped(.ReclaimableMap).start();
            defer map_timer.end_and_log();
            // TODO: better flags
            for (kernel.physical_address_space.reclaimable) |region| {
                // This needs an specific offset since the kernel value "higher_half_direct_map" is not set yet. The to_higher_half_virtual_address() function depends on this value being set.
                // Therefore a manual set here is preferred as a tradeoff with a better runtime later when often calling the aforementioned function
                new_virtual_address_space.map_physical_region(region.descriptor, region.descriptor.address.to_virtual_address_with_offset(higher_half_direct_map), .{
                    .write = true,
                    .user = true,
                });
            }
        }

        {
            var map_timer = Timer.Scoped(.Framebuffer).start();
            defer map_timer.end_and_log();
            // TODO: better flags
            for (kernel.physical_address_space.framebuffer) |region| {
                // This needs an specific offset since the kernel value "higher_half_direct_map" is not set yet. The to_higher_half_virtual_address() function depends on this value being set.
                // Therefore a manual set here is preferred as a tradeoff with a better runtime later when often calling the aforementioned function
                new_virtual_address_space.map_physical_region(region, region.address.to_virtual_address_with_offset(higher_half_direct_map), .{
                    .write = true,
                    .user = true,
                });
            }
        }

        new_virtual_address_space.make_current();
        new_virtual_address_space.copy_to_new(&kernel.virtual_address_space);
        kernel.higher_half_direct_map = VirtualAddress.new(higher_half_direct_map);

        // Update identity-mapped pointers to higher-half ones
        {
            var ptr = kernel.physical_address_space.usable.ptr;
            const len = kernel.physical_address_space.usable.len;
            _ = ptr;
            const ptrtoint = @ptrToInt(ptr);
            _ = ptrtoint;
            const final_address = ptrtoint + higher_half_direct_map;
            ptr = @intToPtr([*]PhysicalAddressSpace.MapEntry, final_address);
            kernel.physical_address_space.usable = ptr[0..len];
        }
        {
            var ptr = kernel.physical_address_space.reclaimable.ptr;
            const len = kernel.physical_address_space.reclaimable.len;
            const ptrtoint = @ptrToInt(ptr);
            _ = ptr;
            _ = len;
            const final_address = ptrtoint + higher_half_direct_map;
            ptr = @intToPtr([*]PhysicalAddressSpace.MapEntry, final_address);
            kernel.physical_address_space.reclaimable = ptr[0..len];
        }
        {
            var ptr = kernel.physical_address_space.framebuffer.ptr;
            const len = kernel.physical_address_space.framebuffer.len;
            const ptrtoint = @ptrToInt(ptr);
            const final_address = ptrtoint + higher_half_direct_map;
            ptr = @intToPtr([*]PhysicalMemoryRegion, final_address);
            kernel.physical_address_space.framebuffer = ptr[0..len];
        }
        {
            var ptr = kernel.physical_address_space.reserved.ptr;
            const len = kernel.physical_address_space.reserved.len;
            const ptrtoint = @ptrToInt(ptr);
            const final_address = ptrtoint + higher_half_direct_map;
            ptr = @intToPtr([*]PhysicalMemoryRegion, final_address);
            kernel.physical_address_space.reserved = ptr[0..len];
        }
        {
            var ptr = kernel.physical_address_space.kernel_and_modules.ptr;
            const len = kernel.physical_address_space.kernel_and_modules.len;
            const ptrtoint = @ptrToInt(ptr);
            const final_address = ptrtoint + higher_half_direct_map;
            ptr = @intToPtr([*]PhysicalMemoryRegion, final_address);
            kernel.physical_address_space.kernel_and_modules = ptr[0..len];
        }

        stivale_log.debug("Memory mapping initialized!", .{});

        {
            var reclaimable_consuming_timer = Timer.Scoped(.ConsumeReclaimable).start();
            defer reclaimable_consuming_timer.end_and_log();

            for (kernel.physical_address_space.reclaimable) |*region| {
                const bitset = region.get_bitset_extended();
                const bitset_size = bitset.len * @sizeOf(PhysicalAddressSpace.MapEntry.BitsetBaseType);
                region.allocated_size = std.align_forward(bitset_size, page_size);
                region.setup_bitset();
            }

            const old_reclaimable = kernel.physical_address_space.reclaimable.len;
            const now_usable_ptr = kernel.physical_address_space.usable.ptr;
            const now_usable_length = kernel.physical_address_space.usable.len;
            // @ZigBug This crashes the compiler. Can't find minimal repro
            //kernel.physical_address_space.usable.len += old_reclaimable;
            kernel.physical_address_space.usable = now_usable_ptr[0 .. now_usable_length + old_reclaimable];
            // Empty the reclaimable memory array since we have recovered everything
            // TODO: don't make reclaimable memory a member of physical address space if the memory is reclaimed here
            // Setting slice len here also crashes the compiler
            kernel.physical_address_space.reclaimable = &.{};

            //stivale_log.debug("Reclaimed reclaimable physical memory. Counting with {} more regions", .{old_reclaimable});
        }

        // TODO: Handle virtual memory management later on
        stivale_log.debug("Paging initialized", .{});
    }

    // Compute again the struct
    stivale2_struct = stivale2_struct_physical_address.access_kernel(*Struct);

    {
        const pmrs_struct = find(stivale.Struct.PMRs, stivale2_struct) orelse @panic("PMRs struct not found");
        const pmrs = pmrs_struct.pmrs()[0..pmrs_struct.entry_count];
        if (pmrs.len == 0) @panic("PMRs empty");

        std.assert(kernel.virtual_address_space.lock.status == 0);
        kernel.sections_in_memory = kernel.virtual_address_space.heap.allocator.alloc(VirtualMemoryRegion, pmrs.len) catch @panic("failed to allocate memory for PMRs");

        for (pmrs) |pmr, i| {
            const kernel_section = &kernel.sections_in_memory[i];
            kernel_section.address = VirtualAddress.new(pmr.address);
            kernel_section.size = pmr.size;
            //const permissions = pmr.permissions;
            //kernel_section.read = permissions & (1 << stivale.Struct.PMRs.PMR.readable) != 0;
            //kernel_section.write = permissions & (1 << stivale.Struct.PMRs.PMR.writable) != 0;
            //kernel_section.execute = permissions & (1 << stivale.Struct.PMRs.PMR.executable) != 0;
        }
        stivale_log.debug("Processed sections in memory", .{});
    }

    // This procedure copies the kernel file in a region which is usable and whose allocationcan be registered in the physical allocator bitset
    {
        const kernel_file_struct = find(stivale.Struct.KernelFileV2, stivale2_struct) orelse @panic("Kernel file struct not found");
        const file_address = PhysicalAddress.new(kernel_file_struct.kernel_file);
        const file_size = kernel_file_struct.kernel_size;
        // TODO: consider alignment?
        stivale_log.debug("allocation about to happen", .{});
        const dst = kernel.virtual_address_space.heap.allocator.alloc(u8, file_size) catch @panic("Unable to allocate memory for kernel file");
        stivale_log.debug("allocation did happen", .{});
        const src = file_address.access_kernel([*]u8)[0..file_size];
        stivale_log.debug("Copying kernel file to (0x{x}, 0x{x})", .{ @ptrToInt(dst.ptr), @ptrToInt(dst.ptr) + dst.len });
        std.copy(u8, dst, src);
        kernel.file = FileInMemory{
            .address = VirtualAddress.new(@ptrToInt(dst.ptr)),
            .size = file_size,
        };
        stivale_log.debug("Processed kernel file in memory", .{});
    }

    {
        const stivale_framebuffer = find(stivale.Struct.Framebuffer, stivale2_struct) orelse @panic("Framebuffer struct not found");
        std.assert(stivale_framebuffer.framebuffer_pitch % stivale_framebuffer.framebuffer_width == 0);
        std.assert(stivale_framebuffer.framebuffer_bpp % @bitSizeOf(u8) == 0);
        const bytes_per_pixel = @intCast(u8, stivale_framebuffer.framebuffer_bpp / @bitSizeOf(u8));
        std.assert(stivale_framebuffer.framebuffer_pitch / stivale_framebuffer.framebuffer_width == bytes_per_pixel);
        kernel.bootloader_framebuffer = Framebuffer{
            .virtual_address = PhysicalAddress.new(stivale_framebuffer.framebuffer_addr).to_higher_half_virtual_address(),
            .width = stivale_framebuffer.framebuffer_width,
            .height = stivale_framebuffer.framebuffer_height,
            .bytes_per_pixel = bytes_per_pixel,
            .red_mask = .{ .size = stivale_framebuffer.red_mask_size, .shift = stivale_framebuffer.red_mask_shift },
            .blue_mask = .{ .size = stivale_framebuffer.blue_mask_size, .shift = stivale_framebuffer.blue_mask_shift },
            .green_mask = .{ .size = stivale_framebuffer.green_mask_size, .shift = stivale_framebuffer.green_mask_shift },
        };
        stivale_log.debug("Processed framebuffer", .{});
    }

    {
        cpu_initialization_context = CPUInitializationContext{
            .kernel_virtual_address_space = &kernel.virtual_address_space,
            .scheduler = &kernel.scheduler,
        };

        const smp_struct = find(stivale.Struct.SMP, stivale2_struct) orelse @panic("SMP struct not found");
        stivale_log.debug("SMP struct: {}", .{smp_struct});

        const cpu_count = smp_struct.cpu_count;
        const smps = smp_struct.smp_info()[0..cpu_count];
        std.assert(smps[0].lapic_id == smp_struct.bsp_lapic_id);
        // @Allocation
        bootstrap_context.cpu.idle_thread = &foo;
        bootstrap_context.cpu.idle_thread.context = &foo2;
        bootstrap_context.cpu.idle_thread.context = &foo2;
        bootstrap_context.cpu.idle_thread.address_space = &kernel.virtual_address_space;
        bootstrap_context.thread.context = &foo2;
        bootstrap_context.thread.address_space = &kernel.virtual_address_space;

        kernel.scheduler.lock.acquire();

        const threads = kernel.scheduler.thread_buffer.add_many(kernel.virtual_address_space.heap.allocator, cpu_count) catch @panic("wtf");
        kernel.scheduler.current_threads = kernel.virtual_address_space.heap.allocator.alloc(*Thread, threads.len) catch @panic("wtf");
        const thread_stack_size = Scheduler.default_kernel_stack_size;
        const thread_bulk_stack_allocation_size = threads.len * thread_stack_size;
        const thread_stacks = kernel.virtual_address_space.allocate(thread_bulk_stack_allocation_size, null, .{ .write = true }) catch @panic("wtF");
        kernel.scheduler.cpus = kernel.virtual_address_space.heap.allocator.alloc(CPU, cpu_count) catch @panic("wtF");
        kernel.scheduler.cpus[0].id = smps[0].processor_id;
        // Dummy context
        TLS.preset(&kernel.scheduler, &kernel.scheduler.cpus[0]);
        TLS.set_current(&kernel.scheduler, &threads[0], &kernel.scheduler.cpus[0]);
        // Map LAPIC address on just one CPU (since it's global)
        CPU.map_lapic(&kernel.virtual_address_space);

        // TODO: ignore BSP cpu when AP initialization?
        for (threads) |*thread, thread_i| {
            kernel.scheduler.current_threads[thread_i] = thread;
            const cpu = &kernel.scheduler.cpus[thread_i];
            const smp = &smps[thread_i];

            const stack_allocation_offset = thread_i * thread_stack_size;
            const kernel_stack_address = thread_stacks.offset(stack_allocation_offset);
            const thread_stack = Scheduler.ThreadStack{
                .kernel = .{ .address = kernel_stack_address, .size = thread_stack_size },
                .user = .{ .address = kernel_stack_address, .size = thread_stack_size },
            };

            const entry_point = @ptrToInt(&kernel_smp_entry);
            kernel.scheduler.initialize_thread(thread, thread_i, &kernel.virtual_address_space, .kernel, .idle, entry_point, thread_stack);
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

        kernel.scheduler.lock.release();

        stivale_log.debug("Processed SMP info", .{});
    }

    const current_thread = TLS.get_current();
    const cpu = current_thread.cpu orelse @panic("cpu");
    cpu.start(&kernel.scheduler, &kernel.virtual_address_space);

    _ = kernel.scheduler.spawn_kernel_thread(&kernel.virtual_address_space, .{
        .address = @ptrToInt(&main),
    });

    VAS.log_map_timer_register();

    entry_point_timer.end_and_log();
    cpu.ready = true;
    while (true) {
        asm volatile (
            \\cli
            \\hlt
        );
    }
    //cpu.make_thread_idle();
}
