const common = @import("common");
pub const panic = common.User.panic;
pub const log = common.User.log;

const Syscall = common.Syscall;
const ask_syscall_manager = Syscall.ask_syscall_manager;
const logger = Syscall.log;

export fn _start() callconv(.C) void {
    const syscall_manager = ask_syscall_manager() orelse @panic("wtf");
    syscall_manager.add_submission(logger("Hello world from userland"));
    syscall_manager.flush();
    while (true) {}
}
