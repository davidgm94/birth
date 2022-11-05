const privileged = @import("privileged");
const PhysicalAddressSpace = privileged.PhysicalAddressSpace;
const VirtualAddress = privileged.VirtualAddress;

pub var bsp_address_space = PhysicalAddressSpace{};
