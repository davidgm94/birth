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
