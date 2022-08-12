const VirtualAddress = @import("virtual_address.zig");
pub const File = struct {
    address: VirtualAddress,
    size: u64,
};
