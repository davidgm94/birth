const lib = @import("lib");
const log = lib.log;
const user = @import("user");
const syscall = user.syscall;

export fn entryPoint() callconv(.Naked) noreturn {
    asm volatile (
        \\push %rbp
        \\mov %rsp, %rbp
        \\jmp main
    );
    unreachable;
}

export var core_id: u32 = 0;

export fn main() callconv(.C) noreturn {
    core_id = syscall.getCoreId();
    log.debug("Hello world! User space initialization from core #{}", .{core_id});
    syscall.shutdown();
}

const Writer = extern struct {
    pub const Error = error{};

    pub fn write(_: void, bytes: []const u8) Error!usize {
        syscall.log(bytes);
        return bytes.len;
    }
};

pub const writer = lib.Writer(void, Writer.Error, Writer.write){ .context = {} };
pub var context: Writer = undefined;
pub const panic = user.zigPanic;

pub const std_options = struct {
    pub fn logFn(comptime level: lib.std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        lib.format(writer, format, args) catch {};
        writer.writeByte('\n') catch {};
        _ = scope;
        _ = level;
    }
};
