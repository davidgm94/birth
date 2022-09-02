const std = @import("../../../../common/std.zig");

const CPUID = @import("../../../../common/arch/x86_64/cpuid.zig");
const crash = @import("../../../crash.zig");
const drivers = @import("../drivers.zig");
const Graphics = @import("../../../../drivers/graphics.zig");
const kernel = @import("../../../kernel.zig");
const main = @import("../../../main.zig").main;
const PhysicalAddress = @import("../../../physical_address.zig");
const Stivale2 = @import("stivale2/stivale2.zig");
const TLS = @import("../../tls.zig");
const Timer = @import("../../../timer.zig");
const VAS = @import("../vas.zig");
const VirtualAddressSpace = @import("../../../virtual_address_space.zig");
const x86_64 = @import("../../common.zig");
const default_logger = @import("../../../log.zig");

var bootstrap_context: Stivale2.BootstrapContext = undefined;

comptime {
    std.reference_all_declarations(@This());
}

pub export fn kernel_entry_point(stivale2_struct_address: u64) callconv(.C) noreturn {
    var timer = Timer.new();
    x86_64.max_physical_address_bit = CPUID.get_max_physical_address_bit();
    kernel.virtual_address_space = VirtualAddressSpace.bootstrapping();
    bootstrap_context.preinit_bsp(&kernel.scheduler, &kernel.virtual_address_space);
    std.log.scoped(.EntryPoint).debug("Hello kernel!", .{});
    std.log.scoped(.EntryPoint).debug("Stivale2 address: 0x{x}", .{stivale2_struct_address});
    const stivale2_struct_physical_address = PhysicalAddress.new(stivale2_struct_address);
    // This is just a cached version, not the global one (which is set after kernel address space initialization)
    const higher_half_direct_map = Stivale2.process_higher_half_direct_map(stivale2_struct_physical_address.access_kernel(*Stivale2.Struct)) catch @panic("Unable to get higher_half_direct_map");
    x86_64.rsdp_physical_address = Stivale2.process_rsdp(stivale2_struct_physical_address.access_kernel(*Stivale2.Struct)) catch @panic("Unable to get RSDP");
    kernel.physical_address_space = Stivale2.process_memory_map(stivale2_struct_physical_address.access_kernel(*Stivale2.Struct)) catch unreachable;
    VAS.init(&kernel.virtual_address_space, &kernel.physical_address_space, Stivale2.get_pmrs(stivale2_struct_physical_address.access_kernel(*Stivale2.Struct)), higher_half_direct_map);
    const bootloader_information = Stivale2.process_bootloader_information(&kernel.virtual_address_space, stivale2_struct_physical_address.access_kernel(*Stivale2.Struct), &bootstrap_context, &kernel.scheduler) catch unreachable;
    kernel.sections_in_memory = bootloader_information.kernel_sections_in_memory;
    kernel.file = bootloader_information.kernel_file;
    kernel.bootloader_framebuffer = bootloader_information.framebuffer;

    const current_thread = TLS.get_current();
    const cpu = current_thread.cpu orelse @panic("cpu");
    cpu.start(&kernel.scheduler, &kernel.virtual_address_space);

    _ = kernel.scheduler.spawn_kernel_thread(&kernel.virtual_address_space, .{
        .address = @ptrToInt(&main),
    });

    const entry_point_cycles = timer.end_and_get_metric();
    std.log.scoped(.EntryPoint).info("Entry point took {} cycles", .{entry_point_cycles});
    cpu.ready = true;
    cpu.make_thread_idle();
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
    crash.panic_extended("{s}", .{message}, @returnAddress(), null);
}
