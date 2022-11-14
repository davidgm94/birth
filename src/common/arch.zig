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
pub const valid_page_sizes = arch.valid_page_sizes;
pub const reverse_valid_page_sizes = arch.reverse_valid_page_sizes;
pub const reasonable_page_size = arch.reasonable_page_size;

pub fn page_shifter(comptime asked_page_size: comptime_int) comptime_int {
    return @ctz(@as(u32, asked_page_size));
}

pub fn page_mask(comptime asked_page_size: comptime_int) comptime_int {
    return asked_page_size - 1;
}
