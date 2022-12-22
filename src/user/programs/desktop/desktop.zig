const Desktop = @This();

const lib = @import("lib");
const Message = lib.Message;
const Window = lib.Window;

const user = @import("user");
const panic = user.panic;

wallpaper_window: *Window = undefined,

fn setup(desktop: *Desktop) !void {
    desktop.wallpaper_window = try create_plain_window();
    @panic("todo desktop setup");
}

fn create_plain_window() !*Window {
    const window = try window_buffer.add_one_statically();
    _ = try user.syscall_manager.syscall(.create_plain_window, .blocking, .{ .user_window = window });
    if (true) @panic("todo implement more stuff");
    return window;
}

pub var window_buffer: lib.List.BufferList(Window, 64, false) = .{};

pub fn send_message(desktop: *Desktop, message: Message) void {
    switch (message.id) {
        .desktop_setup_ui => {
            desktop.setup() catch |err| panic("Unable to start desktop: {}", .{err});
        },
        //else => @compileLog("Not implemented", message.id),
    }
}
