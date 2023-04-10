const lib = @import("lib");
const user = @import("user");
const syscall = user.syscall;

// inline fn exitQEMU(success: lib.QEMU.ExitCode) void {
//     _ = syscall(.{
//         .options = .{
//             .rise = .{
//                 .id = .qemu_exit,
//                 .convention = .rise,
//             },
//         },
//         .arguments = .{ @enumToInt(success), 0, 0, 0, 0, 0 },
//     });
// }

// fn log(message: []const u8) void {
//     _ = syscall(.{
//         .options = .{
//             .rise = .{
//                 .id = .print,
//                 .convention = .rise,
//             },
//         },
//         .arguments = .{ @ptrToInt(message.ptr), message.len, 0, 0, 0, 0 },
//     });
// }

export fn entryPoint() callconv(.Naked) noreturn {
    asm volatile (
        \\push %rbp
        \\mov %rsp, %rbp
        \\jmp main
    );
    unreachable;
}

export fn main() callconv(.C) noreturn {
    // const core_id = user.Syscall.getCoreId() catch @panic("Core id syscall failed");
    // var buffer: [512]u8 = undefined;
    //
    // user.Syscall.logMessage(lib.bufPrint(&buffer, "Core id: {}\n", .{core_id}) catch @panic("format for log message failed")) catch @panic("log message failed");
    while (true) {}

    unreachable;
}

const Writer = extern struct {
    pub const Error = error{};

    pub fn write(_: void, bytes: []const u8) Error!usize {
        while (true) {}
        return bytes.len;
    }
};

pub const writer = lib.Writer(void, Writer.Error, Writer.write){ .context = {} };
pub var context: Writer = undefined;
pub const panic = user.zigPanic;

pub const std_options = struct {
    pub fn logFn(comptime level: lib.std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        lib.format(writer, format, args) catch {};
        _ = scope;
        _ = level;
    }
};
