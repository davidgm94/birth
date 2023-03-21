const lib = @import("lib");
const user = @import("user");
const syscall = user.syscall;

inline fn exitQEMU(success: lib.QEMU.ExitCode) void {
    _ = syscall(.{
        .number = .{
            .number = @enumToInt(lib.Syscall.Rise.qemu_exit),
            .convention = .rise,
        },
        .arguments = .{ @enumToInt(success), 0, 0, 0, 0, 0 },
    });
}

fn log(message: []const u8) void {
    _ = syscall(.{
        .number = .{
            .number = @enumToInt(lib.Syscall.Rise.print),
            .convention = .rise,
        },
        .arguments = .{ @ptrToInt(message.ptr), message.len, 0, 0, 0, 0 },
    });
}

export fn entryPoint() callconv(.C) noreturn {
    log("Hello from userspace\n");
    exitQEMU(.success);
    asm volatile (
        \\1:
        \\jmp 1b
        ::: "memory");

    unreachable;
}
