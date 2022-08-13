const VirtualMemoryRegion = @This();

const common = @import("../common.zig");
const VirtualAddress = common.VirtualAddress;

address: VirtualAddress,
size: u64,

pub fn new(address: VirtualAddress, size: u64) VirtualMemoryRegion {
    return VirtualMemoryRegion{
        .address = address,
        .size = size,
    };
}
