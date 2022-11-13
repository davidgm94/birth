comptime {
    const os = @import("builtin").os.tag;
    switch (os) {
        .uefi, .freestanding => {},
        else => @compileError("This file is not to be compiled with this OS"),
    }
}
const arch = switch (@import("builtin").cpu.arch) {
    .x86_64 => x86_64,
    else => @compileError("Architecture not supported"),
};

pub const x86_64 = @import("arch/x86_64.zig");

pub const page_size = arch.page_size;
pub const page_shifter = arch.page_shifter;
pub const valid_page_sizes = arch.valid_page_sizes;
pub const reverse_valid_page_sizes = arch.reverse_valid_page_sizes;
pub const reasonable_page_size = arch.reasonable_page_size;
