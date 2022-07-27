const common = @import("../common.zig");
const root = @import("root");

const Writer = struct {
    const Error = error{};
    const execution_mode = common.Syscall.ExecutionMode.blocking;

    // TODO: handle errors
    fn write(_: void, bytes: []const u8) Error!usize {
        _ = root.syscall_manager.syscall(.log, execution_mode, .{ .message = bytes });

        return bytes.len;
    }
};

var writer: common.Writer(void, Writer.Error, Writer.write) = undefined;
// TODO: handle locks in userspace
pub fn log(comptime level: common.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    // TODO: handle errors
    writer.print("[" ++ @tagName(level) ++ "] (" ++ @tagName(scope) ++ ") " ++ format, args) catch unreachable;
}

// TODO: improve user panic implementation
pub fn panic(message: []const u8, _: ?*common.StackTrace) noreturn {
    common.log.scoped(.PANIC).err("{s}", .{message});
    while (true) {}
}
