pub fn main() noreturn {
    asm volatile (
        \\cli
        \\hlt
    );
    unreachable;
}
