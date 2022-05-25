const kernel = @import("../kernel.zig");

const limine = @import("x86_64/limine3/limine.zig");
// TODO
pub fn disable_interrupts() void {}

pub const Writer = struct {
    const Error = error{};
    pub var should_lock = false;
    // TODO
    fn write(_: void, bytes: []const u8) Error!usize {
        _ = bytes;
        return 0;
    }
};

pub var writer = kernel.Writer(void, Writer.Error, Writer.write){ .context = {} };

pub export fn _start() noreturn {
    while (true) {}
}

pub export var terminal_request = limine.limine_terminal_request{ .id = limine.limine_terminal_request_id, .revision = 0, .callback = undefined, .response = undefined };
