const VirtualMemoryRegion = @This();

const RNU = @import("RNU");
const VirtualAddress = RNU.VirtualAddress;

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

pub fn access(virtual_memory_region: VirtualMemoryRegion, comptime T: type) []T {
    return virtual_memory_region.address.access([*]T)[0..@divExact(virtual_memory_region.size, @sizeOf(T))];
}
