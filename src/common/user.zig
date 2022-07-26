const common = @import("../common.zig");
const root = @import("root");
pub fn log(comptime level: common.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    _ = level;
    _ = scope;
    _ = format;
    _ = args;
    root.writer.print("[" ++ @tagName(level) ++ "] [" ++ @tagName(scope) ++ "] " ++ format, args) catch unreachable;
}

pub fn panic(message: []const u8, _: ?*common.StackTrace) noreturn {
    _ = message;
    while (true) {}
}
