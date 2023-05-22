const lib = @import("lib");
const log = lib.log;
const user = @import("user");
const syscall = user.syscall;

comptime {
    _ = user;
}

const Writer = extern struct {
    pub const Error = error{
        log_failed,
    };

    pub fn write(_: void, bytes: []const u8) Error!usize {
        return syscall(.io, .log, bytes) catch return Error.log_failed;
    }
};

pub const writer = lib.Writer(void, Writer.Error, Writer.write){ .context = {} };
pub var context: Writer = undefined;
pub const panic = user.zigPanic;

pub const std_options = struct {
    pub fn logFn(comptime level: lib.std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        lib.format(writer, format, args) catch unreachable;
        writer.writeByte('\n') catch unreachable;
        _ = scope;
        _ = level;
    }
};

export var core_id: u32 = 0;

pub fn main() !noreturn {
    core_id = try syscall(.cpu, .get_core_id, {});
    user.currentScheduler().core_id = core_id;
    log.debug("Hello world! User space initialization from core #{}", .{core_id});
    try syscall(.cpu, .shutdown, {});
}
