const VirtualMemoryRegion = @This();

const std = @import("../common/std.zig");
const VirtualAddress = @import("virtual_address.zig");

address: VirtualAddress,
size: u64,

pub fn new(address: VirtualAddress, size: u64) VirtualMemoryRegion {
    return VirtualMemoryRegion{
        .address = address,
        .size = size,
    };
}

pub fn access_bytes(virtual_memory_region: VirtualMemoryRegion) []u8 {
    return virtual_memory_region.address.access([*]u8)[0..virtual_memory_region.size];
}
