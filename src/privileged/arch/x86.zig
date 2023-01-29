pub const io = @import("x86/io.zig");

pub fn stopCPU() noreturn {
    while (true) {
        asm volatile (
            \\cli
            \\hlt
            \\pause
            ::: "memory");
    }
}

pub const paging = struct {
    pub const Specific = extern struct {
        foo: u32,
    };
};
