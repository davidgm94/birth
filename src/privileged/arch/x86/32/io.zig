pub inline fn writeBytes(port: u16, bytes: []const u8) usize {
    const bytes_left = asm volatile (
        \\cld
        \\rep outsb
        : [ret] "={ecx}" (-> usize),
        : [dest] "{dx}" (port),
          [src] "{esi}" (bytes.ptr),
          [len] "{ecx}" (bytes.len),
    );
    return bytes.len - bytes_left;
}
