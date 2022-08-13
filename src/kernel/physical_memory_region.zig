const Region = @This();
const PhysicalAddress = @import("physical_address.zig");
address: PhysicalAddress,
size: u64,

pub fn new(address: PhysicalAddress, size: u64) Region {
    return Region{
        .address = address,
        .size = size,
    };
}
