const std = @import("../../../common/std.zig");
const user = @import("../../common.zig");
pub const panic = user.panic;
pub const log = user.log;
pub const logger = std.log.scoped(.main);

const Syscall = @import("../../syscall.zig");
pub var syscall_manager: *Syscall.Manager = undefined;

export fn user_entry_point() callconv(.C) void {
    //syscall_manager = Syscall.Manager.ask() orelse @panic("wtf");
    //logger.debug("Hello world from userspace", .{});
    //const file = syscall_manager.syscall(.read_file, .blocking, .{ .name = "zap-light16.psf" });
    //for (file[0..10]) |byte, byte_i| {
    //logger.debug("{}: 0x{x}", .{ byte_i, byte });
    //}
    //const memory = syscall_manager.syscall(.allocate_memory, .blocking, .{ .byte_count = 5001, .alignment = 1 });
    //_ = memory;
    //syscall_manager.syscall(.thread_exit, .blocking, .{ .message = "Thread terminated successfully" });
    while (true) {}
}
