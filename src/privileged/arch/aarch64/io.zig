pub inline fn writeBytes(port: u16, bytes: []const u8) error{}!usize {
    _ = bytes;
    _ = port;

    @panic("TODO writeBytes");
}

pub inline fn write(comptime T: type, port: u16, value: T) void {
    _ = port;
    _ = value;
    @panic("TODO write");
}
