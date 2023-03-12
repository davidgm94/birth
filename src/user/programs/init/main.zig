export fn entryPoint() callconv(.Naked) noreturn {
    asm volatile ("syscall" ::: "memory");
    asm volatile (
        \\1:
        \\jmp 1b
        ::: "memory");

    unreachable;
}
