pub const paging = @import("riscv64/paging.zig");
pub const io = @import("riscv64/io.zig");

pub inline fn disableInterrupts() void {
    asm volatile ("" ::: "memory");
    @panic("TODO disableInterrupts");
}

pub inline fn stopCPU() noreturn {
    while (true) {
        disableInterrupts();
        asm volatile ("wfi" ::: "memory");
    }
}
