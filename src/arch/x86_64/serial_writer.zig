const io = @import("io.zig");

pub const Error = error{};
pub const Context = void;

pub fn write(context: Context, bytes: []const u8) Error!usize {
    _ = context;

    for (bytes) |byte| {
        io.write(u8, io.Ports.E9_hack, byte);
    }

    return bytes.len;
}
