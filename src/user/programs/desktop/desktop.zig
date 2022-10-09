const common = @import("common");
const Message = common.Message;

fn setup() void {
    @panic("todo desktop setup");
}

fn create_plain_window() *Window!void {
    const window = try window_buffer.add_one_statically();
    if (true) @panic("todo plain window");
    return window;
}

const Window = struct {};

pub var window_buffer: common.List.BufferList(Window, 64, false) = .{};

pub fn send_message(message: Message) void {
    switch (message.id) {
        .desktop_setup_ui => {
            setup();
        },
        //else => @compileLog("Not implemented", message.id),
    }
}
