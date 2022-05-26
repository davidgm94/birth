const kernel = @import("../kernel.zig");

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
