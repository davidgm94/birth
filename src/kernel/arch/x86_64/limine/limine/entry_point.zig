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
const VirtualAddress = @import("../../../../virtual_address.zig");
const VirtualMemoryRegion = @import("../../../../virtual_memory_region.zig");
const PhysicalAddress = @import("../../../../physical_address.zig");
const PhysicalAddressSpace = @import("../../../../physical_address_space.zig");
const PhysicalMemoryRegion = @import("../../../../physical_memory_region.zig");
const Scheduler = @import("../../../../scheduler.zig");
const Thread = @import("../../../../thread.zig");

const logger = std.log.scoped(.Limine);

const PhysicalAllocator = struct {
    zero_free_list: List = .{},
    free_list: List = .{},
};

const List = struct {
    first: ?*FreePhysicalRegion = null,
    last: ?*FreePhysicalRegion = null,
    count: u64 = 0,
};

const Descriptor = struct {
    address: PhysicalAddress,
    size: u64,
};

const Flags = packed struct(u64) {
    zeroed: bool = false,
};

const FreePhysicalRegion = struct {
    descriptor: Descriptor,
    previous: ?*FreePhysicalRegion = null,
    next: ?*FreePhysicalRegion = null,
};

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
        const usable_free_regions = kernel.bootstrap_allocator.allocator().alloc(FreePhysicalRegion, usable_entry_count) catch @panic("Unable to allocate usable free regions");
        var maybe_last: ?*FreePhysicalRegion = null;
        var usable_i: u64 = 0;

        for (entries) |entry| {
            if (entry.type == .usable) {
                const region = &usable_free_regions[usable_i];
                defer {
                    usable_i += 1;
                    if (maybe_last) |last| last.next = region;
                    maybe_last = region;
                }
                region.* = FreePhysicalRegion{
                    .descriptor = Descriptor{
                        .address = PhysicalAddress.new(entry.address),
                        .size = entry.size,
                    },
                    .previous = maybe_last,
                };
            }
        }

        var physical_allocator = PhysicalAllocator{
            .zero_free_list = List{
                .first = &usable_free_regions[0],
                .last = maybe_last,
                .count = usable_entry_count,
            },
        };
        _ = physical_allocator;
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
