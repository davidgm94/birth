const common = @import("../common.zig");
pub fn log(comptime level: common.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    _ = level;
    _ = scope;
    _ = format;
    _ = args;
    unreachable;
}

pub fn panic(message: []const u8, _: ?*common.StackTrace) noreturn {
    _ = message;
    while (true) {}
}
