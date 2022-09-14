const std = @import("../../../../../common/std.zig");

const common = @import("../../../../common.zig");
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

const Framebuffer = common.Framebuffer;
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

    const memory_map_response = bootloader_memory_map.response orelse @panic("Memory map response not present");
    const memory_map_entry_count = memory_map_response.entry_count;
    const memory_map_ptr_to_entry_ptr = memory_map_response.entries orelse @panic("Pointer to memory map entry pointer is null");
    const memory_map_entry_ptr = memory_map_ptr_to_entry_ptr.*;
    const memory_map_entries = memory_map_entry_ptr[0..memory_map_entry_count];
    {
        var usable_entry_count: u64 = 0;
        for (memory_map_entries) |entry| {
            usable_entry_count += @boolToInt(entry.type == .usable);
        }

        logger.debug("Usable entry count: {}", .{usable_entry_count});
        const usable_free_regions = kernel.bootstrap_allocator.allocator().alloc(PhysicalAddressSpace.FreePhysicalRegion, usable_entry_count) catch @panic("Unable to allocate usable free regions");
        var maybe_last: ?*PhysicalAddressSpace.FreePhysicalRegion = null;
        var usable_i: u64 = 0;

        for (memory_map_entries) |entry| {
            logger.debug("Physical memory region: {s}, (0x{x}, 0x{x})", .{ @tagName(entry.type), entry.address, entry.address + entry.size });
            switch (entry.type) {
                .usable => {
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
                },
                else => {},
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

    const kernel_address_response = bootloader_kernel_address.response orelse @panic("Kernel address response not present");
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

            logger.debug("Kernel address. PA: 0x{x}. VA: 0x{x}", .{ kernel_address_response.physical_address, kernel_address_response.virtual_address });
            const kernel_base_physical_address = PhysicalAddress.new(kernel_address_response.physical_address);
            const kernel_base_virtual_address = VirtualAddress.new(kernel_address_response.virtual_address);
            // TODO: no execute

            for (memory_map_entries) |entry| {
                if (entry.type == .usable) {
                    const entry_physical_address = PhysicalAddress.new(entry.address);
                    logger.debug("Mapping usable region: ({}, {})", .{ entry_physical_address, entry_physical_address.offset(entry.size) });
                    VAS.bootstrap_map(entry_physical_address, entry_physical_address.to_higher_half_virtual_address(), @divExact(entry.size, x86_64.page_size), .{ .write = true });
                }
            }

            logger.debug("Ended mapping usable", .{});

            map_section("text", kernel_base_physical_address, kernel_base_virtual_address, .{ .execute = true });
            map_section("rodata", kernel_base_physical_address, kernel_base_virtual_address, .{ .execute = false });
            map_section("data", kernel_base_physical_address, kernel_base_virtual_address, .{ .write = true, .execute = false });

            for (memory_map_entries) |entry| {
                if (entry.type != .kernel_and_modules and entry.type != .usable and entry.type != .reserved) {
                    logger.debug("Mapping {s} region", .{@tagName(entry.type)});
                    const entry_physical_address = PhysicalAddress.new(entry.address);
                    VAS.bootstrap_map(entry_physical_address, entry_physical_address.to_higher_half_virtual_address(), @divExact(entry.size, x86_64.page_size), .{ .write = true });
                }
            }
        }

        // TODO: reclaimable, framebuffer, reserved, etc

        {
            kernel.virtual_address_space.make_current();
            kernel.virtual_address_space.copy_to_new(&kernel.virtual_address_space);
        }

        kernel.memory_initialized = true;
        logger.debug("memory initialized", .{});

        {
            // Use the bootstrap allocator since we don't want any allocation happening here
            kernel.virtual_address_space.used_regions.ensureTotalCapacity(kernel.bootstrap_allocator.allocator(), 512) catch unreachable;
            kernel.virtual_address_space.free_regions.ensureTotalCapacity(kernel.bootstrap_allocator.allocator(), 512) catch unreachable;

            for (memory_map_entries) |entry| {
                const entry_physical_address = PhysicalAddress.new(entry.address);
                switch (entry.type) {
                    .usable, .bootloader_reclaimable, .framebuffer => {
                        _ = @divExact(entry.size, x86_64.page_size);
                        const entry_virtual_address = entry_physical_address.to_higher_half_virtual_address();

                        const region = VirtualAddressSpace.Region{
                            .address = entry_virtual_address,
                            .size = entry.size,
                            .flags = VirtualAddressSpace.Flags{
                                .write = true,
                            },
                        };

                        kernel.virtual_address_space.add_used_region(region) catch unreachable;
                    },
                    .kernel_and_modules => {
                        if (entry.address == kernel_address_response.physical_address) {
                            const region = VirtualAddressSpace.Region{
                                .address = VirtualAddress.new(kernel_address_response.virtual_address),
                                .size = entry.size,
                                // TODO: write proper flags
                                .flags = .{},
                            };
                            kernel.virtual_address_space.add_used_region(region) catch unreachable;
                        }
                    },
                    .reserved => {
                        // TODO:
                        // TODO: check if we should the same as above or not. For now, repeat it
                        //_ = @divExact(entry.size, x86_64.page_size);
                        //const entry_virtual_address = entry_physical_address.to_higher_half_virtual_address();

                        //const region = VirtualAddressSpace.Region{
                        //.address = entry_virtual_address,
                        //.size = entry.size,
                        //.flags = VirtualAddressSpace.Flags{
                        //.write = true,
                        //},
                        //};

                        //kernel.virtual_address_space.add_used_region(region) catch unreachable;
                    },
                    else => crash.panic("ni: {}", .{entry.type}),
                }
            }
        }

        //// TODO: Handle virtual memory management later on
        logger.debug("Paging initialized", .{});
    }

    kernel.physical_address_space.log_free_memory();

    {
        const response = bootloader_framebuffer.response orelse @panic("Framebuffer response not found");
        if (response.framebuffer_count == 0) @panic("No framebuffer found");
        const ptr_framebuffer_ptr = response.framebuffers orelse @panic("Framebuffer response has an invalid pointer");
        const framebuffer_ptr = ptr_framebuffer_ptr.*;
        const framebuffers = framebuffer_ptr[0..response.framebuffer_count];
        std.assert(framebuffers.len == 1);
        const framebuffer = framebuffers[0];
        std.assert(framebuffer.pitch % framebuffer.width == 0);
        std.assert(framebuffer.bpp % @bitSizeOf(u8) == 0);
        const bytes_per_pixel = @intCast(u8, framebuffer.bpp / @bitSizeOf(u8));
        std.assert(framebuffer.pitch / framebuffer.width == bytes_per_pixel);

        // TODO: Make sure this correspnds with the framebuffer region
        //const mapped_address = kernel.bootstrap_virtual_address_space.translate_address(VirtualAddress.new(framebuffer.address)) orelse unreachable;
        //logger.debug("Mapped address: {}", .{mapped_address});

        // For now ignore virtual address since we are using our own mapping
        //
        // TODO: make sure there is just an entry here
        const framebuffer_virtual_address = blk: {
            for (memory_map_entries) |entry| {
                if (entry.type == .framebuffer) {
                    break :blk PhysicalAddress.new(entry.address).to_higher_half_virtual_address();
                }
            }

            unreachable;
        };

        kernel.bootloader_framebuffer = Framebuffer{
            .virtual_address = framebuffer_virtual_address,
            .width = framebuffer.width,
            .height = framebuffer.height,
            .bytes_per_pixel = bytes_per_pixel,
            .red_mask = .{ .size = framebuffer.red_mask_size, .shift = framebuffer.red_mask_shift },
            .blue_mask = .{ .size = framebuffer.blue_mask_size, .shift = framebuffer.blue_mask_shift },
            .green_mask = .{ .size = framebuffer.green_mask_size, .shift = framebuffer.green_mask_shift },
        };
        logger.debug("Processed framebuffer", .{});
    }

    {
        const response = bootloader_smp.response orelse @panic("SMP response not found");
        const cpu_count = response.cpu_count;
        if (cpu_count == 0) @panic("SMP response has no CPU information");
        const ptr_cpu_ptr = response.cpus orelse @panic("SMP response has an invalid pointer to CPU data structures");
        const cpu_ptr = ptr_cpu_ptr.*;
        const cpus = cpu_ptr[0..cpu_count];

        for (cpus) |cpu| {
            logger.debug("CPU {}", .{cpu});
        }
    }

    logger.debug("Congrats! Reached to the end", .{});

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

fn map_section(comptime section_name: []const u8, kernel_base_physical_address: PhysicalAddress, kernel_base_virtual_address: VirtualAddress, flags: VirtualAddressSpace.Flags) void {
    const section_start = @extern(*u8, .{ .name = section_name ++ "_section_start" });
    const section_end = @extern(*u8, .{ .name = section_name ++ "_section_end" });

    const virtual_address = VirtualAddress.new(@ptrToInt(section_start));
    const physical_address = PhysicalAddress.new(virtual_address.value - kernel_base_virtual_address.value + kernel_base_physical_address.value);
    const size = @ptrToInt(section_end) - @ptrToInt(section_start);
    const page_count = @divExact(size, x86_64.page_size);

    logger.debug("Mapping kernel section {s} ({}, {}) ({}, {})", .{ section_name, physical_address, physical_address.offset(size), virtual_address, virtual_address.offset(size) });
    VAS.bootstrap_map(physical_address, virtual_address, page_count, flags);
}

/// Define root.log_level to override the default
pub const log_level: std.log.Level = switch (std.build_mode) {
    .Debug => .debug,
    .ReleaseSafe => .debug,
    .ReleaseFast, .ReleaseSmall => .debug,
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
