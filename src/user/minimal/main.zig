const common = @import("common");
pub const panic = common.User.panic;
pub const log = common.User.log;
pub const logger = common.log.scoped(.main);

const Syscall = common.Syscall;
const ask_syscall_manager = Syscall.ask_syscall_manager;
pub var syscall_manager: *Syscall.Manager = undefined;

export fn _start() callconv(.C) void {
    syscall_manager = Syscall.Manager.ask() orelse @panic("wtf");
    logger.debug("Hello world from userspace", .{});
    logger.debug("About to page fault", .{});
    @intToPtr(*volatile u8, 0xffff_ffff_9000_0000).* = 0;
    syscall_manager.syscall(.thread_exit, .blocking, .{ .message = "Thread terminated successfully" });
    while (true) {}
}
