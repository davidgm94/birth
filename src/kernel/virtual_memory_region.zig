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
