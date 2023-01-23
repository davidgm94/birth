const lib = @import("lib");
const privileged = @import("privileged");

pub const x86 = @import("arch/x86.zig");
pub const x86_64 = @import("arch/x86_64.zig");

const arch = switch (lib.cpu.arch) {
    .x86 => x86,
    .x86_64 => x86_64,
    else => @compileError("Architecture not supported"),
};

pub const CoreDirectorShared = arch.CoreDirectorShared;
pub const CPU_stop = arch.CPU_stop;
pub const paging = arch.paging;
pub const Registers = arch.Registers;

pub const dispatch_count = arch.dispatch_count;
pub var max_physical_address_bit: u6 = 40;

pub const io = arch.io;

pub const PhysicalAddress = arch.PhysicalAddress;
pub const VirtualAddress = arch.VirtualAddress;
pub const PhysicalMemoryRegion = arch.PhysicalMemoryRegion;
pub const VirtualMemoryRegion = arch.VirtualMemoryRegion;
pub const VirtualAddressSpace = arch.VirtualAddressSpace;
