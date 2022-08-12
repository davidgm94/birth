pub const ISADebugExit = struct {
    port: u16,
    size: u16,
};

pub const x86_64_debug_exit = ISADebugExit{
    .port = 0xf4,
    .size = @sizeOf(u32),
};
