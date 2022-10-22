// This package provides of privileged data structures and routines to both kernel and bootloaders, for now
const crash = @import("privileged/crash.zig");
pub const panic = crash.panic;
pub const panic_extended = crash.panic_extended;

pub const Heap = @import("privileged/heap.zig");
pub const PhysicalAddress = @import("privileged/physical_address.zig");
pub const PhysicalAddressSpace = @import("privileged/physical_address_space.zig");
pub const PhysicalMemoryRegion = @import("privileged/physical_memory_region.zig");
pub const UEFI = @import("privileged/uefi.zig");
pub const VirtualAddress = @import("privileged/virtual_address.zig");
pub const VirtualAddressSpace = @import("privileged/virtual_address_space.zig");
pub const VirtualMemoryRegion = @import("privileged/virtual_memory_region.zig");

pub const ResourceOwner = enum(u2) {
    bootloader = 0,
    kernel = 1,
    user = 2,
};
