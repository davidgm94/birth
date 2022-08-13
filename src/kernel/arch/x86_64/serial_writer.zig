pub const Error = error{};
pub const Context = void;

pub fn write(context: Context, bytes: []const u8) Error!usize {
    _ = context;
    for (bytes) |byte| {
        _ = byte;
        @panic("wtF");
        //io_write(u8, IOPort.E9_hack, byte);
    }

    return bytes.len;
}
