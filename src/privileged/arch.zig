const arch = switch (@import("builtin").cpu.arch) {
    .x86_64 => x86_64,
    else => @compileError("Architecture not supported"),
};

pub const x86_64 = @import("arch/x86_64.zig");

pub const CoreDirector = arch.CoreDirector;
pub const CPU_stop = arch.CPU_stop;
pub const paging = arch.paging;

pub const dispatch_count = arch.dispatch_count;
pub var max_physical_address_bit: u6 = 40;
