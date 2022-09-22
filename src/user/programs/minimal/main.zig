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
    const bitmap = STBTrueType.initialize(file);

    //var height: u32 = 0;
    //while (height < @intCast(u32, bitmap.height)) : (height += 1) {
    //var width: u32 = 0;
    //while (width < @intCast(u32, bitmap.width)) : (width += 1) {
    //logger.debug("[H: {}][W: {}]: 0x{x}", .{ height, width, bitmap.ptr[height * @intCast(u32, bitmap.width) + width] });
    //}
    //}

    const framebuffer = syscall_manager.syscall(.get_framebuffer, .blocking, .{});
    var height: u32 = 0;
    while (height < bitmap.height) : (height += 1) {
        const bitmap_row = bitmap.ptr[bitmap.width * height .. (height + 1) * bitmap.width];
        const framebuffer_slice = @intToPtr([*]u8, framebuffer.virtual_address)[height * framebuffer.width * framebuffer.bytes_per_pixel .. (height + 1) * (framebuffer.width) * framebuffer.bytes_per_pixel];
        std.copy(u8, framebuffer_slice, bitmap_row);
    }

    syscall_manager.syscall(.thread_exit, .blocking, .{ .message = "Thread terminated successfully" });
    while (true) {}
}
