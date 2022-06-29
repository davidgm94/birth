/// Define root.log_level to override the default
pub const log_level: kernel.log.Level = switch (common.build_mode) {
    .Debug => .debug,
    .ReleaseSafe => .debug,
    .ReleaseFast, .ReleaseSmall => .info,
};

pub fn log(comptime level: kernel.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";

    //var time: [20]u8 = undefined; // 20 should be enough for 64 bit system
    //const buffer = time[0..];
    //const time_str = kernel.fmt.bufPrint(buffer, "{d:>6}", .{@intToFloat(f64, kernel.arch.Clock.TICK) / @intToFloat(f64, kernel.arch.HZ)}) catch @panic("Unexpected format error in root.log");
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;

    //kernel.arch.writer.writeAll("[") catch unreachable;
    //kernel.arch.writer.writeAll(time_str) catch unreachable;
    //kernel.arch.writer.writeAll("] ") catch unreachable;
    kernel.arch.Writer.lock.acquire();
    kernel.arch.writer.print(prefix ++ format ++ "\n", args) catch unreachable;
    kernel.arch.Writer.lock.release();
}

//var panicking: usize = 0;
pub fn panic(message: []const u8, _: ?*kernel.StackTrace) noreturn {
    kernel.crash("{s}", .{message});
}
