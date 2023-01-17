const lib = @import("lib");
const privileged = @import("privileged");

const writer = privileged.E9Writer{ .context = {} };

export fn entry_point() callconv(.Naked) noreturn {
    asm volatile(
        \\jmp *%[main_function]
    :
    : [main_function] "r" (main)
    );

    while (true) {}
}

export fn main() noreturn {
    writer.writeAll("Stage 2\n") catch unreachable;
    while (true) {
    }
}
