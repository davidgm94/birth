comptime {
    const os = @import("builtin").os.tag;
    switch (os) {
        .uefi, .freestanding => {},
        else => @compileError("This file is not to be compiled with this OS"),
    }
}

pub const current = switch (@import("builtin").cpu.arch) {
    .x86 => x86,
    .x86_64 => x86_64,
    else => @compileError("Architecture not supported"),
};

pub const x86 = @import("arch/x86.zig");
pub const x86_64 = @import("arch/x86_64.zig");

pub const default_page_size = current.default_page_size;
pub const reasonable_page_size = current.reasonable_page_size;

pub const valid_page_sizes = current.valid_page_sizes;
pub const reverse_valid_page_sizes = current.reverse_valid_page_sizes;

pub fn page_shifter(comptime asked_page_size: comptime_int) comptime_int {
    return @ctz(@as(u32, asked_page_size));
}

pub fn page_mask(comptime asked_page_size: comptime_int) comptime_int {
    return asked_page_size - 1;
}

pub const Spinlock = current.Spinlock;

pub const stack_alignment = current.stack_alignment;
