const common = @import("../common.zig");
const root = @import("root");

const Writer = struct {
    const Error = error{};
    const execution_mode = common.Syscall.ExecutionMode.blocking;
    var lock: Lock = undefined;

    // TODO: handle errors
    fn write(_: void, bytes: []const u8) Error!usize {
        _ = root.syscall_manager.syscall(.log, execution_mode, .{ .message = bytes });

        return bytes.len;
    }
};

const Lock = struct {
    status: u8,

    fn acquire(lock: *Lock) void {
        const expected: @TypeOf(lock.status) = 0;
        while (@cmpxchgStrong(@TypeOf(lock.status), @ptrCast(*@TypeOf(lock.status), &lock.status), expected, ~expected, .Acquire, .Monotonic) != null) {
            asm volatile ("pause" ::: "memory");
        }
        @fence(.Acquire);
    }
    fn release(lock: *Lock) void {
        const expected = ~@as(@TypeOf(lock.status), 0);
        lock.assert_status(expected);
        @fence(.Release);
        lock.status = 0;
    }

    fn assert_status(lock: *Lock, expected: u8) void {
        if (lock.status != expected) {
            @panic("User lock wtf");
        }
    }
};

var writer: common.Writer(void, Writer.Error, Writer.write) = undefined;

// TODO: handle locks in userspace
// TODO: handle errors
pub fn log(comptime level: common.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    var buffer: [0x2000]u8 = undefined;
    _ = buffer;
    Writer.lock.acquire();
    defer Writer.lock.release();
    const resulting_slice = common.bufPrint(&buffer, "[" ++ @tagName(level) ++ "] (" ++ @tagName(scope) ++ ") " ++ format, args) catch unreachable;
    writer.writeAll(resulting_slice) catch unreachable;
}

// TODO: improve user panic implementation
pub fn panic(message: []const u8, _: ?*common.StackTrace) noreturn {
    common.log.scoped(.PANIC).err("{s}", .{message});
    while (true) {}
}
