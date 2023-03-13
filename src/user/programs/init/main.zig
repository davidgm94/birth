const lib = @import("lib");
const user = @import("user");
const syscall = user.syscall;

export fn entryPoint() callconv(.C) noreturn {
    _ = syscall(.{
        .number = .{
            .number = @enumToInt(lib.Syscall.Rise.qemu_exit),
            .convention = .rise,
        },
        .arguments = .{ @enumToInt(lib.QEMU.ExitCode.success), 0, 0, 0, 0, 0 },
    });
    asm volatile (
        \\1:
        \\jmp 1b
        ::: "memory");

    unreachable;
}
