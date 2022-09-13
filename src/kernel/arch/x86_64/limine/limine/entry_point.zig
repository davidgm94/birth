const std = @import("../../../../../common/std.zig");

const CPUID = @import("../../../../../common/arch/x86_64/cpuid.zig");
const crash = @import("../../../../crash.zig");
const default_logger = @import("../../../../log.zig");
const kernel = @import("../../../../kernel.zig");
const Limine = @import("limine.zig");
const TLS = @import("../../tls.zig");
const x86_64 = @import("../../common.zig");

const Context = @import("../../context.zig");
const CPU = @import("../../cpu.zig");
const Heap = @import("../../../../heap.zig");
const PhysicalAddress = @import("../../../../physical_address.zig");
const PhysicalAddressSpace = @import("../../../../physical_address_space.zig");
const PhysicalMemoryRegion = @import("../../../../physical_memory_region.zig");
const Scheduler = @import("../../../../scheduler.zig");
const Spinlock = @import("../../../../spinlock.zig");
const Thread = @import("../../../../thread.zig");
const VAS = @import("../../vas.zig");
const VirtualAddress = @import("../../../../virtual_address.zig");
const VirtualMemoryRegion = @import("../../../../virtual_memory_region.zig");
const VirtualAddressSpace = @import("../../../../virtual_address_space.zig");

const logger = std.log.scoped(.Limine);

pub export fn kernel_entry_point() noreturn {
    CPU.early_bsp_bootstrap();

    logger.debug("Hello kernel!", .{});

    kernel.higher_half_direct_map = blk: {
        const response = bootloader_hhdm.response orelse @panic("HHDM response not present");
        if (response.offset == 0) @panic("No offset in HHDM response");
        break :blk VirtualAddress.new(response.offset);
    };
    logger.debug("HHDM: {}", .{kernel.higher_half_direct_map});

    x86_64.rsdp_physical_address = blk: {
        const response = bootloader_rsdp.response orelse @panic("RSDP response not present");
        if (response.address == 0) @panic("RSDP address is null");
        break :blk response.address;
    };
    logger.debug("RSDP: 0x{x}", .{x86_64.rsdp_physical_address});

    {
        const response = bootloader_memory_map.response orelse @panic("Memory map response not present");
        const entry_count = response.entry_count;
        const ptr_to_entry_ptr = response.entries orelse @panic("Pointer to memory map entry pointer is null");
        const entry_ptr = ptr_to_entry_ptr.*;
        const entries = entry_ptr[0..entry_count];
        var usable_entry_count: u64 = 0;
        for (entries) |entry| {
            usable_entry_count += @boolToInt(entry.type == .usable);
        }

        logger.debug("Usable entry count: {}", .{usable_entry_count});
        const usable_free_regions = kernel.bootstrap_allocator.allocator().alloc(PhysicalAddressSpace.FreePhysicalRegion, usable_entry_count) catch @panic("Unable to allocate usable free regions");
        var maybe_last: ?*PhysicalAddressSpace.FreePhysicalRegion = null;
        var usable_i: u64 = 0;

        for (entries) |entry| {
            if (entry.type == .usable) {
                const region = &usable_free_regions[usable_i];
                defer {
                    usable_i += 1;
                    if (maybe_last) |last| last.next = region;
                    maybe_last = region;
                }
                region.* = PhysicalAddressSpace.FreePhysicalRegion{
                    .descriptor = PhysicalMemoryRegion{
                        .address = PhysicalAddress.new(entry.address),
                        .size = entry.size,
                    },
                    .previous = maybe_last,
                };
            }
        }

        kernel.physical_address_space = PhysicalAddressSpace{
            .zero_free_list = .{
                .first = &usable_free_regions[0],
                .last = maybe_last,
                .count = usable_entry_count,
            },
        };
    }

    // Init paging
    {
        // Kernel address space initialization
        kernel.bootstrap_virtual_address_space = kernel.bootstrap_allocator.allocator().create(VirtualAddressSpace) catch @panic("bootstrap allocator failed");
        VirtualAddressSpace.from_current(kernel.bootstrap_virtual_address_space);

        kernel.virtual_address_space = VirtualAddressSpace{
            .arch = .{},
            .privilege_level = .kernel,
            .heap = Heap.new(&kernel.virtual_address_space),
            .lock = Spinlock{},
            .valid = false,
        };

        VAS.new(&kernel.virtual_address_space, &kernel.physical_address_space);
        std.log.scoped(.CR3).debug("New kernel address space CR3 0x{x}", .{@bitCast(u64, kernel.virtual_address_space.arch.cr3)});

        // Map the kernel and do some tests
        {
            std.log.scoped(.MyMap).debug("Starting mapping kernel executable", .{});

            @panic("TODO map the kernel");
            // TODO: better flags
            //for (stivale_pmrs) |pmr| {
            //defer std.log.scoped(.MyMap).debug("Mapped section", .{});
            //const section_virtual_address = VirtualAddress.new(pmr.address);
            //const section_page_count = @divExact(pmr.size, x86_64.page_size);

            //const section_physical_address = kernel.bootstrap_virtual_address_space.translate_address(section_virtual_address) orelse @panic("Section not mapped");
            //std.log.scoped(.Section).debug("Section PA: {}. VA: {}", .{ section_physical_address, section_virtual_address });

            //VAS.bootstrap_map(section_physical_address, section_virtual_address, section_page_count, .{
            //.execute = pmr.permissions & Struct.PMRs.PMR.executable != 0,
            //.write = true, //const writable = permissions & Stivale2.Struct.PMRs.PMR.writable != 0;
            //});
            //}
        }

        //var mapping_pages_mapped = x86_64.VAS.bootstrapping_physical_addresses.items.len;
        {
            std.log.scoped(.MyMap).debug("Starting mapping usable regions", .{});

            @panic("TODO map usable");
            // TODO: better flags
            //for (kernel.physical_address_space.usable) |region| {
            // This needs an specific offset since the kernel value "higher_half_direct_map" is not set yet. The to_higher_half_virtual_address() function depends on this value being set.
            // Therefore a manual set here is preferred as a tradeoff with a better runtime later when often calling the aforementioned function
            //const physical_address = region.descriptor.address;
            //const virtual_address = region.descriptor.address.to_higher_half_virtual_address();
            //const page_count = @divExact(region.allocated_size, x86_64.page_size);
            //std.log.scoped(.Mappppp).debug("Mapping (0x{x}, 0x{x}) to (0x{x}, 0x{x})", .{ physical_address.value, physical_address.offset(region.allocated_size).value, virtual_address.value, virtual_address.offset(region.allocated_size).value });
            //VAS.bootstrap_map(physical_address, virtual_address, page_count, .{
            //.write = true,
            //});
            //}
        }

        {
            @panic("TODO map reclaimable");
            // TODO: better flags
            //for (kernel.physical_address_space.reclaimable) |region| {
            //// This needs an specific offset since the kernel value "higher_half_direct_map" is not set yet. The to_higher_half_virtual_address() function depends on this value being set.
            //// Therefore a manual set here is preferred as a tradeoff with a better runtime later when often calling the aforementioned function
            //std.assert(std.is_aligned(region.descriptor.size, x86_64.page_size));
            //VAS.bootstrap_map(region.descriptor.address, region.descriptor.address.to_higher_half_virtual_address(), region.descriptor.size / x86_64.page_size, .{
            //.write = true,
            //});
            //}
        }

        {
            @panic("TODO map framebuffer");
            // TODO: better flags
            //for (kernel.physical_address_space.framebuffer) |region| {
            //// This needs an specific offset since the kernel value "higher_half_direct_map" is not set yet. The to_higher_half_virtual_address() function depends on this value being set.
            //// Therefore a manual set here is preferred as a tradeoff with a better runtime later when often calling the aforementioned function
            //std.assert(std.is_aligned(region.size, x86_64.page_size));
            //VAS.bootstrap_map(region.address, region.address.to_higher_half_virtual_address(), region.size / x86_64.page_size, .{
            //.write = true,
            //});
            //}
        }

        @panic("TODO all");

        // Make sure we have mapped all the needed pages. This assumes some pages were needed in order to allocate
        // page tables when mapping
        //std.assert(mapping_pages_mapped != x86_64.VAS.bootstrapping_physical_addresses.items.len);
        // Make sure the read is volatile
        //while (mapping_pages_mapped < x86_64.VAS.bootstrapping_physical_addresses.items.len) : (mapping_pages_mapped += 1) {
        //const physical_address = x86_64.VAS.bootstrapping_physical_addresses.items[mapping_pages_mapped];
        //std.log.scoped(.MappingPage).debug("Mapping 0x{x}", .{physical_address.value});
        //const virtual_address = physical_address.to_higher_half_virtual_address();
        //VAS.bootstrap_map(physical_address, virtual_address, 1, .{ .write = true });
        //}

        //kernel.virtual_address_space.make_current();
        //kernel.virtual_address_space.copy_to_new(&kernel.virtual_address_space);

        //// Update identity-mapped pointers to higher-half ones
        //{
        //var ptr = kernel.physical_address_space.usable.ptr;
        //const len = kernel.physical_address_space.usable.len;
        //_ = ptr;
        //const ptrtoint = @ptrToInt(ptr);
        //_ = ptrtoint;
        //const final_address = kernel.higher_half_direct_map.offset(ptrtoint);
        //ptr = final_address.access([*]PhysicalAddressSpace.MapEntry);
        //kernel.physical_address_space.usable = ptr[0..len];
        //}
        //{
        //var ptr = kernel.physical_address_space.reclaimable.ptr;
        //const len = kernel.physical_address_space.reclaimable.len;
        //const ptrtoint = @ptrToInt(ptr);
        //_ = ptr;
        //_ = len;
        //const final_address = kernel.higher_half_direct_map.offset(ptrtoint);
        //ptr = final_address.access([*]PhysicalAddressSpace.MapEntry);
        //kernel.physical_address_space.reclaimable = ptr[0..len];
        //}
        //{
        //var ptr = kernel.physical_address_space.framebuffer.ptr;
        //const len = kernel.physical_address_space.framebuffer.len;
        //const ptrtoint = @ptrToInt(ptr);
        //const final_address = kernel.higher_half_direct_map.offset(ptrtoint);
        //ptr = final_address.access([*]PhysicalMemoryRegion);
        //kernel.physical_address_space.framebuffer = ptr[0..len];
        //}
        //{
        //var ptr = kernel.physical_address_space.reserved.ptr;
        //const len = kernel.physical_address_space.reserved.len;
        //const ptrtoint = @ptrToInt(ptr);
        //const final_address = kernel.higher_half_direct_map.offset(ptrtoint);
        //ptr = final_address.access([*]PhysicalMemoryRegion);
        //kernel.physical_address_space.reserved = ptr[0..len];
        //}
        //{
        //var ptr = kernel.physical_address_space.kernel_and_modules.ptr;
        //const len = kernel.physical_address_space.kernel_and_modules.len;
        //const ptrtoint = @ptrToInt(ptr);
        //const final_address = kernel.higher_half_direct_map.offset(ptrtoint);
        //ptr = final_address.access([*]PhysicalMemoryRegion);
        //kernel.physical_address_space.kernel_and_modules = ptr[0..len];
        //}

        //logger.debug("Memory mapping initialized!", .{});

        //{
        //for (kernel.physical_address_space.reclaimable) |*region| {
        //const bitset = region.get_bitset_extended();
        //const bitset_size = bitset.len * @sizeOf(PhysicalAddressSpace.MapEntry.BitsetBaseType);
        //region.allocated_size = std.align_forward(bitset_size, page_size);
        //region.setup_bitset();
        //}

        //const old_reclaimable = kernel.physical_address_space.reclaimable.len;
        //const now_usable_ptr = kernel.physical_address_space.usable.ptr;
        //const now_usable_length = kernel.physical_address_space.usable.len;
        //// @ZigBug This crashes the compiler. Can't find minimal repro
        ////kernel.physical_address_space.usable.len += old_reclaimable;
        //kernel.physical_address_space.usable = now_usable_ptr[0 .. now_usable_length + old_reclaimable];
        //// Empty the reclaimable memory array since we have recovered everything
        //// TODO: don't make reclaimable memory a member of physical address space if the memory is reclaimed here
        //// Setting slice len here also crashes the compiler
        //kernel.physical_address_space.reclaimable = &.{};

        ////stivale_log.debug("Reclaimed reclaimable physical memory. Counting with {} more regions", .{old_reclaimable});
        //}

        //kernel.memory_initialized = true;

        //{
        //// Use the bootstrap allocator since we don't want any allocation happening here
        //kernel.virtual_address_space.used_regions.ensureTotalCapacity(kernel.bootstrap_allocator.allocator(), 512) catch unreachable;
        //kernel.virtual_address_space.free_regions.ensureTotalCapacity(kernel.bootstrap_allocator.allocator(), 512) catch unreachable;

        //for (kernel.physical_address_space.usable) |*map_entry| {
        //// Track all of it as linearly mapped for now
        //const address = map_entry.descriptor.address;
        //const total_page_count = @divExact(map_entry.descriptor.size, x86_64.page_size);
        //const allocated_page_count = @divExact(map_entry.allocated_size, x86_64.page_size);
        //const free_page_count = total_page_count - allocated_page_count;

        //if (allocated_page_count != 0) {
        //const region = VirtualAddressSpace.Region{
        //.address = address.to_higher_half_virtual_address(),
        //.page_count = allocated_page_count,
        //.flags = VirtualAddressSpace.Flags{
        //.write = true,
        //},
        //};

        //std.log.scoped(.Track).debug("Tracked used region: (0x{x}, {})", .{ region.address.value, region.page_count });

        //kernel.virtual_address_space.add_used_region(region) catch unreachable;
        //}

        //if (free_page_count != 0) {
        //const region = VirtualAddressSpace.Region{
        //.address = address.to_higher_half_virtual_address().offset(allocated_page_count * x86_64.page_size),
        //.page_count = free_page_count,
        //.flags = VirtualAddressSpace.Flags{
        //.write = true,
        //},
        //};

        //std.log.scoped(.Track).debug("Tracked free region: (0x{x}, {})", .{ region.address.value, region.page_count });

        //kernel.virtual_address_space.add_free_region(region) catch unreachable;
        //}
        //}

        //for (kernel.physical_address_space.framebuffer) |framebuffer_physical_region| {
        //std.log.scoped(.Track).debug("Framebuffer physical region: (0x{x}, {})", .{ framebuffer_physical_region.address.value, framebuffer_physical_region.size });
        //const physical_address = framebuffer_physical_region.address;
        //const virtual_address = physical_address.to_higher_half_virtual_address();
        //const page_count = @divExact(framebuffer_physical_region.size, x86_64.page_size);

        //const region = VirtualAddressSpace.Region{
        //.address = virtual_address,
        //.page_count = page_count,
        //.flags = VirtualAddressSpace.Flags{
        //.write = true,
        //},
        //};

        //std.log.scoped(.Track).debug("Tracked framebuffer region: (0x{x}, {})", .{ region.address.value, region.page_count });

        //kernel.virtual_address_space.add_used_region(region) catch unreachable;
        //}

        //for (kernel.physical_address_space.kernel_and_modules) |kernel_and_modules_physical_region| {
        //std.log.scoped(.Track).debug("Kernel and modules physical region: (0x{x}, {})", .{ kernel_and_modules_physical_region.address.value, kernel_and_modules_physical_region.size });
        //const physical_address = kernel_and_modules_physical_region.address;
        //const virtual_address = physical_address.to_higher_half_virtual_address();
        //const page_count = @divExact(kernel_and_modules_physical_region.size, x86_64.page_size);

        //const region = VirtualAddressSpace.Region{
        //.address = virtual_address,
        //.page_count = page_count,
        //// TODO: rewrite flags
        //.flags = VirtualAddressSpace.Flags{},
        //};

        //std.log.scoped(.Track).debug("Tracked kernel and modules region: (0x{x}, {})", .{ region.address.value, region.page_count });

        //kernel.virtual_address_space.add_used_region(region) catch unreachable;
        //}

        //// Lock down reserved region identity-mapped virtual addresses just in case
        //for (kernel.physical_address_space.reserved) |reserved_physical_region| {
        //std.log.scoped(.Track).debug("Reserved physical region: (0x{x}, {})", .{ reserved_physical_region.address.value, reserved_physical_region.size });

        //const physical_address = reserved_physical_region.address;
        //const virtual_address = VirtualAddress.new(physical_address.value);

        //if (kernel.virtual_address_space.translate_address(virtual_address)) |mapped_physical_address| {
        //std.log.scoped(.Track).debug("Reserved identity virtual address 0x{x} is mapped to 0x{x}", .{ virtual_address.value, mapped_physical_address.value });
        //@panic("WTF");
        //}

        //const page_count = std.div_ceil(u64, reserved_physical_region.size, x86_64.page_size) catch unreachable;

        //const region = VirtualAddressSpace.Region{
        //.address = virtual_address,
        //.page_count = page_count,
        //// TODO: rewrite flags
        //.flags = VirtualAddressSpace.Flags{},
        //};

        //std.log.scoped(.Track).debug("Tracked reserved region: (0x{x}, {})", .{ region.address.value, region.page_count });

        //kernel.virtual_address_space.add_used_region(region) catch unreachable;
        //}
        //}

        //// TODO: Handle virtual memory management later on
        //stivale_log.debug("Paging initialized", .{});
    }

    while (true) {}
}

export var bootloader_info = Limine.BootloaderInfo.Request{
    .revision = 0,
};

export var bootloader_hhdm = Limine.HHDM.Request{
    .revision = 0,
};

export var bootloader_framebuffer = Limine.Framebuffer.Request{
    .revision = 0,
};

export var bootloader_smp = Limine.SMPInfo.Request{
    .revision = 0,
    .flags = 0,
};

export var bootloader_memory_map = Limine.MemoryMap.Request{
    .revision = 0,
};

export var bootloader_entry_point = Limine.EntryPoint.Request{
    .revision = 0,
    .entry_point = kernel_entry_point,
};

export var bootloader_kernel_file = Limine.KernelFile.Request{
    .revision = 0,
};

export var bootloader_rsdp = Limine.RSDP.Request{
    .revision = 0,
};

export var bootloader_boot_time = Limine.BootTime.Request{
    .revision = 0,
};

export var bootloader_kernel_address = Limine.KernelAddress.Request{
    .revision = 0,
};

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
