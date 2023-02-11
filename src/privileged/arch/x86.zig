const x86 = @import("x86/common.zig");
pub usingnamespace x86;

pub const io = @import("x86/32/io.zig");

pub fn stopCPU() noreturn {
    while (true) {
        asm volatile (
            \\cli
            \\hlt
            \\pause
            ::: "memory");
    }
}

pub inline fn disableInterrupts() void {
    asm volatile ("cli" ::: "memory");
}

pub const paging = struct {
    pub const Specific = extern struct {
        foo: u32,
    };
};
