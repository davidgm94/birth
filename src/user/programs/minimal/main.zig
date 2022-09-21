const std = @import("../../../common/std.zig");
const user = @import("../../common.zig");
const STBTrueType = @import("../../dependencies/stb_truetype/stb_truetype.zig");
pub const panic = user.panic;
pub const log = user.log;
pub const logger = std.log.scoped(.main);

const Syscall = @import("../../syscall.zig");
pub var syscall_manager: *Syscall.Manager = undefined;

export fn user_entry_point() callconv(.C) void {
    //std.assert(user.Writer.lock.status == 0xff or user.Writer.lock.status == 0);
    syscall_manager = Syscall.Manager.ask() orelse @panic("wtf");
    //std.assert(user.Writer.lock.status == 0xff or user.Writer.lock.status == 0);
    logger.debug("Hello world from userspace", .{});
    //std.assert(user.Writer.lock.status == 0xff or user.Writer.lock.status == 0);
    const file = syscall_manager.syscall(.read_file, .blocking, .{ .name = "FiraSans-Regular.otf" });
    STBTrueType.initialize(file);
    syscall_manager.syscall(.thread_exit, .blocking, .{ .message = "Thread terminated successfully" });
    while (true) {}
}
