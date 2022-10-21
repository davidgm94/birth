export fn kernel_entry_point() callconv(.Naked) noreturn {
    asm volatile (
        \\cli
        \\hlt
    );
    unreachable;
}
