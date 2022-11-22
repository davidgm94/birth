comptime {
    asm (
        \\.section .text
        \\.code16
        \\hang:
        \\cli
        \\hlt
    );
}
export fn _start() noreturn {
    while (true) {}
}
