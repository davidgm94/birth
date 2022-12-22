const lib = @import("lib");
const assert = lib.assert;
const field_size = lib.fieldSize;
pub const logger = lib.log.scoped(.main);

const Desktop = @import("desktop.zig");
const Message = lib.Message;

const user = @import("user");
pub const panic = user.zig_panic;
pub const log = user.zig_log;
const Syscall = user.Syscall;

//const text = @import("../../text.zig");

pub var desktop: Desktop = .{};

fn send_message(message: Message) !void {
    _ = try user.syscall_manager.syscall(.send_message, .blocking, .{ .message = message });
}

fn receive_message() !Message {
    const message = try user.syscall_manager.syscall(.receive_message, .blocking, {});
    return message;
}

export fn user_entry_point() callconv(.C) void {
    user.syscall_manager = Syscall.Manager.ask() orelse @panic("wtf");

    send_message(Message{ .id = .desktop_setup_ui, .context = null }) catch unreachable;

    while (true) {
        const message = receive_message() catch unreachable;
        desktop.send_message(message);
    }
}
