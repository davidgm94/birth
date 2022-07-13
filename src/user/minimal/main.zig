const common = @import("common");
const thread_exit = common.Syscall.thread_exit;
export fn _start() callconv(.C) void {
    thread_exit(0, 0, 0, 0, 0);
    while (true) {}
}

pub fn log(comptime level: common.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    _ = level;
    _ = scope;
    _ = format;
    _ = args;
    unreachable;
}
