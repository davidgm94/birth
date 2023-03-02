const lib = @import("lib");
const assert = lib.assert;

pub inline fn stopCPU() noreturn {
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

pub const SegmentDescriptor = extern struct {
    limit: u16,
    address: u64 align(2),

    comptime {
        assert(@sizeOf(@This()) == 10);
    }
};
