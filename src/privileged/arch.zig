const lib = @import("../lib.zig");
const privileged = @import("../privileged.zig");

pub const x86 = @import("arch/x86.zig");
pub const x86_64 = @import("arch/x86_64.zig");

const arch = switch (lib.cpu.arch) {
    .x86 => x86,
    .x86_64 => x86_64,
    else => @compileError("Architecture not supported"),
};

pub const CoreDirectorShared = arch.CoreDirectorShared;
pub const stopCPU = arch.stopCPU;
pub const paging = arch.paging;
pub const Registers = arch.Registers;
pub const disableInterrupts = arch.disableInterrupts;

pub const dispatch_count = arch.dispatch_count;
pub var max_physical_address_bit: u6 = 40;

pub const io = arch.io;

const AddressInterface = privileged.Address.Interface(u64);
pub const PhysicalAddress = AddressInterface.PhysicalAddress;
pub const VirtualAddress = AddressInterface.VirtualAddress;
pub const PhysicalMemoryRegion = AddressInterface.PhysicalMemoryRegion;
pub const VirtualMemoryRegion = AddressInterface.VirtualMemoryRegion;
pub const VirtualAddressSpace = AddressInterface.VirtualAddressSpace(lib.cpu.arch);
