const common = @import("common");
pub const panic = common.User.panic;
pub const log = common.User.log;
pub const logger = common.log.scoped(.main);

const Syscall = common.Syscall;
const ask_syscall_manager = Syscall.ask_syscall_manager;
pub var syscall_manager: *Syscall.Manager = undefined;

export fn _start() callconv(.C) void {
    syscall_manager = ask_syscall_manager() orelse @panic("wtf");
    logger.debug("Hello world from userspace", .{});
    syscall_manager.syscall(.thread_exit, .blocking, .{ .message = "Thread terminated successfully" });
    while (true) {}
}
