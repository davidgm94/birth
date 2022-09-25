const PhysicalAddress = @import("physical_address.zig");
const VirtualAddress = @import("virtual_address.zig");

pub const FileInMemory = struct {
    address: VirtualAddress,
    size: u64,
};
