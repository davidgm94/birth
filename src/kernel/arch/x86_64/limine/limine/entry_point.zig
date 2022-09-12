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
const PhysicalAddressSpace = @import("../../../../physical_address_space.zig");
const PhysicalMemoryRegion = @import("../../../../physical_memory_region.zig");
const Scheduler = @import("../../../../scheduler.zig");
const Thread = @import("../../../../thread.zig");

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
