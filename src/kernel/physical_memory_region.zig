const PhysicalMemoryRegion = @This();

const PhysicalAddress = @import("physical_address.zig");
const VirtualAddress = @import("physical_address.zig");
const VirtualMemoryRegion = @import("virtual_memory_region.zig");

address: PhysicalAddress,
size: u64,

pub fn to_higher_half_virtual_address(physical_memory_region: PhysicalMemoryRegion) VirtualMemoryRegion {
    return VirtualMemoryRegion{
        .address = physical_memory_region.address.to_higher_half_virtual_address(),
        .size = physical_memory_region.size,
    };
}
