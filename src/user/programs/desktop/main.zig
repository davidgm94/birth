const common = @import("common");
const assert = common.assert;
const field_size = common.field_size;
pub const logger = common.log.scoped(.main);
const Message = common.Message;

const user = @import("user");
pub const panic = user.panic;
pub const log = user.log;
const Syscall = user.Syscall;

//const text = @import("../../text.zig");

pub var syscall_manager: *Syscall.Manager = undefined;

fn send_message(id: Message.ID, context: ?*anyopaque) void {
    _ = syscall_manager.syscall(.send_message, .blocking, .{ .id = id, .context = context });
}

fn receive_message() Message {
    const message = syscall_manager.syscall(.receive_message, .blocking, .{});
    return message;
}

export fn user_entry_point() callconv(.C) void {
    syscall_manager = Syscall.Manager.ask() orelse @panic("wtf");

    send_message(.desktop_setup_ui, null);

    //const file = syscall_manager.syscall(.read_file, .blocking, .{ .name = "FiraSans-Regular.otf" });
    //const font = text.load_font_from_file(file) catch unreachable;
    //const bitmap = font.create_bitmap_for_text("Zig", 64.0, 512, 128);

    //const framebuffer = syscall_manager.syscall(.get_framebuffer, .blocking, .{});
    //var height: u32 = 0;

    //while (height < bitmap.height) : (height += 1) {
    //const bitmap_row = bitmap.ptr[bitmap.width * height .. (height + 1) * bitmap.width];
    //const framebuffer_offset_index = height * framebuffer.width;
    //for (bitmap_row) |bitmap_byte, i| {
    //const bitmap_u32 = @as(u32, bitmap_byte);
    //const index = framebuffer_offset_index + i;
    //@ptrCast([*]u32, @alignCast(@alignOf(u32), framebuffer.bytes))[index] = (bitmap_u32 << 24) | (bitmap_u32 << 16) | (bitmap_u32 << 8) | (bitmap_u32 << 0);
    //}
    //}

    //syscall_manager.syscall(.thread_exit, .blocking, .{ .message = "Thread terminated successfully" });
    while (true) {}
}
