const Desktop = @This();

const common = @import("common");
const Message = common.Message;
const Window = common.Window;

const user = @import("user");
const panic = user.panic;

wallpaper_window: *Window = undefined,

fn setup(desktop: *Desktop) !void {
    desktop.wallpaper_window = try create_plain_window();
    @panic("todo desktop setup");
}

fn create_plain_window() !*Window {
    const window = try user.syscall_manager.syscall(.create_plain_window, .blocking, .{});
    _ = window;
    @panic("todo create_plain_window");
    //return window;
}

pub var window_buffer: common.List.BufferList(Window, 64, false) = .{};

pub fn send_message(desktop: *Desktop, message: Message) void {
    switch (message.id) {
        .desktop_setup_ui => {
            desktop.setup() catch |err| panic("Unable to start desktop: {}", .{err});
        },
        //else => @compileLog("Not implemented", message.id),
    }
}
