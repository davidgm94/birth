const privileged = @import("privileged");
pub inline fn writeBytes(port: u16, bytes: []const u8) usize {
    const bytes_left = asm volatile (
        \\rep outsb
        : [ret] "={ecx}" (-> usize),
        : [dest] "{dx}" (port),
          [src] "{esi}" (bytes.ptr),
          [len] "{ecx}" (bytes.len),
        : "esi", "ecx"
    );
    return bytes.len - bytes_left;
}
pub const read = privileged.arch.x86.read;
pub const write = privileged.arch.x86.write;
