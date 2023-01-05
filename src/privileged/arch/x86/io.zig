pub inline fn write_bytes(bytes: []const u8) usize {
    const bytes_left = asm volatile (
        \\cld
        \\rep outsb
        : [ret] "={ecx}" (-> usize),
        : [dest] "{dx}" (0xe9),
          [src] "{esi}" (bytes.ptr),
          [len] "{ecx}" (bytes.len),
    );
    return bytes.len - bytes_left;
}
