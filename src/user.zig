comptime {
    if (common.os != .freestanding) @compileError("This file is not meant to be imported in build.zig");
    if (!@hasDecl(root, "syscall_manager")) @compileError("User root file must have syscall manager");
}

const root = @import("root");

const common = @import("common");
const ExecutionMode = common.Syscall.ExecutionMode;

pub const Syscall = @import("user/syscall.zig");

pub const Writer = struct {
    const Error = error{};
    const execution_mode = ExecutionMode.blocking;
    pub var lock = Lock{};

    // TODO: handle errors
    fn write(_: void, bytes: []const u8) Error!usize {
        _ = root.syscall_manager.syscall(.log, execution_mode, .{ .message = bytes });

        return bytes.len;
    }
};

const Lock = struct {
    status: u8 = 0,

    fn acquire(lock: *volatile Lock) void {
        if (lock.status != 0 and lock.status != 0xff) {
            var foo: u64 = 0;
            foo += 1;
        }

        const expected: @TypeOf(lock.status) = 0;
        while (@cmpxchgStrong(@TypeOf(lock.status), &lock.status, expected, ~expected, .Acquire, .Monotonic) == null) {
            asm volatile ("pause" ::: "memory");
        }
        @fence(.Acquire);

        if (lock.status != 0 and lock.status != 0xff) {
            var foo: u64 = 0;
            foo += 1;
        }
    }

    fn release(lock: *volatile Lock) void {
        if (lock.status != 0 and lock.status != 0xff) {
            var foo: u64 = 0;
            while (true) {
                foo += 1;
            }
        }

        const expected = ~@as(@TypeOf(lock.status), 0);
        lock.assert_status(expected);
        @fence(.Release);
        lock.status = 0;

        if (lock.status != 0 and lock.status != 0xff) {
            var foo: u64 = 0;
            while (true) {
                foo += 1;
            }
        }
    }

    fn assert_status(lock: *volatile Lock, expected: u8) void {
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
    Writer.lock.acquire();
    defer Writer.lock.release();
    const resulting_slice = common.bufPrint(&buffer, "[" ++ @tagName(level) ++ "] (" ++ @tagName(scope) ++ ") " ++ format, args) catch unreachable;
    writer.writeAll(resulting_slice) catch unreachable;
}

// TODO: improve user panic implementation
pub fn panic(message: []const u8, _: ?*common.StackTrace, _: ?usize) noreturn {
    common.log.scoped(.PANIC).err("{s}", .{message});
    while (true) {}
}
