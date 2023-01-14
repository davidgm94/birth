pub const io = @import("x86/io.zig");

pub fn CPU_stop() noreturn {
    while (true) {
        asm volatile (
            \\cli
            \\hlt
            \\pause
            ::: "memory");
    }
}

pub const paging = struct {};
