const arch = switch (@import("builtin").cpu.arch) {
    .x86_64 => x86_64,
    else => @compileError("Architecture not supported"),
};

pub const x86_64 = @import("arch/x86_64.zig");

pub const CoreDirector = arch.CoreDirector;
pub const CPU_stop = arch.CPU_stop;
pub const paging = arch.paging;

pub const dispatch_count = arch.dispatch_count;
pub const page_size = arch.page_size;
pub const page_shifter = arch.page_shifter;
pub const valid_page_sizes = arch.valid_page_sizes;
pub const reverse_valid_page_sizes = arch.reverse_valid_page_sizes;
pub const reasonable_page_size = arch.reasonable_page_size;

pub var max_physical_address_bit: u6 = 40;
