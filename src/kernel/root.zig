const std = @import("std");
const builtin = @import("builtin");
const kernel = @import("kernel.zig");
/// Define root.log_level to override the default
pub const log_level: std.log.Level = switch (builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe => .debug,
    .ReleaseFast, .ReleaseSmall => .info,
};

pub fn log(comptime level: std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";

    var time: [20]u8 = undefined; // 20 should be enough for 64 bit system
    const buffer = time[0..];
    const time_str = std.fmt.bufPrint(buffer, "{d:>6}", .{@intToFloat(f64, kernel.arch.Clock.TICK) / @intToFloat(f64, kernel.arch.HZ)}) catch @panic("Unexpected format error in root.log");
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;

    kernel.arch.writer.writeAll("[") catch unreachable;
    kernel.arch.writer.writeAll(time_str) catch unreachable;
    kernel.arch.writer.writeAll("] ") catch unreachable;
    kernel.arch.writer.print(prefix ++ format ++ "\n", args) catch unreachable;
}

var panicking: usize = 0;
pub fn panic(message: []const u8, _: ?*std.builtin.StackTrace) noreturn {
    @setCold(true);
    kernel.arch.disable_interrupts();

    if (panicking != 0) {
        kernel.arch.writer.writeAll("\npanicked during kernel panic!\n") catch unreachable;
        kernel.arch.spinloop();
    }

    _ = @atomicRmw(usize, &panicking, .Add, 1, .SeqCst);
    std.log.err("KERNEL PANIC: {s}", .{message});

    kernel.arch.writer.writeAll("\n") catch unreachable;
    kernel.arch.writer.writeAll("\n") catch unreachable;
    kernel.arch.writer.writeAll("\n") catch unreachable;
    kernel.arch.spinloop();
}
