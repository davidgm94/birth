const common = @import("common");
pub const panic = common.User.panic;
pub const log = common.User.log;

const thread_exit = common.Syscall.thread_exit;

export fn _start() callconv(.C) void {
    thread_exit(.{
        .exit_code = 0,
        .message = "Hello kernel from userspace",
    });
    while (true) {}
}
