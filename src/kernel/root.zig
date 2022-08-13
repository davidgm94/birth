const std = @import("../common/std.zig");
const TLS = @import("arch/tls.zig");
const default_log_writer = @import("arch/default_log_writer.zig");

pub fn log(comptime level: std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
    const current_thread = TLS.get_current();
    const current_cpu = current_thread.cpu orelse while (true) {};
    const processor_id = current_cpu.id;
    default_log_writer.lock.acquire();
    defer default_log_writer.lock.release();
    default_log_writer.writer.print("[Kernel] [Core #{}] [Thread #{}] ", .{ processor_id, current_thread.id }) catch unreachable;
    default_log_writer.writer.writeAll(prefix) catch unreachable;
    default_log_writer.writer.print(format, args) catch unreachable;
    default_log_writer.writer.writeByte('\n') catch unreachable;
}

//var panicking: usize = 0;
pub fn panic(message: []const u8, _: ?*std.StackTrace) noreturn {
    std.log.err("Panic happened: {s}", .{message});
    while (true) {}
}
