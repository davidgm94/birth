const lib = @import("lib");
const log = lib.log;
const user = @import("user");
const Syscall = user.Syscall;

comptime {
    _ = user;
}

const Writer = extern struct {
    pub const Syscall = user.Syscall(.io, .log);
    pub const Error = Writer.Syscall.ErrorSet.Error;

    pub fn write(_: void, bytes: []const u8) Error!usize {
        const result = try Writer.Syscall.blocking(bytes);
        return result;
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
    core_id = try Syscall(.cpu, .get_core_id).blocking({});
    user.currentScheduler().core_id = core_id;
    log.debug("Hello world! User space initialization from core #{}", .{core_id});
    try Syscall(.cpu, .shutdown).blocking({});
}
