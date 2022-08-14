const std = @import("../common/std.zig");
const crash = @import("crash.zig");
const EntryPoint = @import("arch/entry_point.zig");
const TLS = @import("arch/tls.zig");
const default_logger = @import("log.zig");

comptime {
    @export(EntryPoint.function, .{ .name = "start", .linkage = .Strong });
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
    const current_thread = TLS.get_current();
    const current_cpu = current_thread.cpu orelse while (true) {};
    const processor_id = current_cpu.id;
    default_logger.lock.acquire();
    defer default_logger.lock.release();
    default_logger.writer.print("[Kernel] [Core #{}] [Thread #{}] ", .{ processor_id, current_thread.id }) catch unreachable;
    default_logger.writer.writeAll(prefix) catch unreachable;
    default_logger.writer.print(format, args) catch unreachable;
    default_logger.writer.writeByte('\n') catch unreachable;
}

//var panicking: usize = 0;
pub fn panic(message: []const u8, _: ?*std.StackTrace) noreturn {
    crash.panic("{s}", .{message});
}
