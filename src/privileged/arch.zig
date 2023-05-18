const lib = @import("lib");
const privileged = @import("privileged");

pub const x86 = @import("arch/x86.zig");
pub const x86_64 = @import("arch/x86_64.zig");

pub const current = switch (lib.cpu.arch) {
    .x86 => x86,
    .x86_64 => x86_64,
    else => @compileError("Architecture not supported"),
};

pub const CPUPageTables = current.paging.CPUPageTables;
pub const stopCPU = current.stopCPU;
pub const paging = current.paging;
pub const Registers = current.Registers;
pub const disableInterrupts = current.disableInterrupts;

pub const dispatch_count = current.dispatch_count;
pub var max_physical_address_bit: u6 = 40;

pub const io = current.io;
