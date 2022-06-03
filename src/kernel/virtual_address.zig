const kernel = @import("kernel.zig");
const Physical = kernel.Physical;
const VirtualAddress = @This();

value: u64,

pub inline fn new(value: u64) VirtualAddress {
    return VirtualAddress{
        .value = value,
    };
}

pub inline fn identity_physical_address(virtual_address: VirtualAddress) Physical.Address {
    return Physical.Address.new(virtual_address.value);
}

pub inline fn page_up(virtual_address: *VirtualAddress) void {
    virtual_address.value += kernel.arch.page_size;
}

pub inline fn is_page_aligned(virtual_address: VirtualAddress) bool {
    return kernel.is_aligned(virtual_address.value, kernel.arch.page_size);
}
