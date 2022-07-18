const common = @import("../common.zig");
const VirtualAddress = @This();
const PhysicalAddress = @import("physical_address.zig");

value: u64,

pub inline fn new(value: u64) VirtualAddress {
    const virtual_address = VirtualAddress{
        .value = value,
    };
    common.runtime_assert(@src(), virtual_address.is_valid());
    return virtual_address;
}

pub inline fn invalid() VirtualAddress {
    return VirtualAddress{
        .value = 0,
    };
}

pub inline fn is_valid(virtual_address: VirtualAddress) bool {
    return virtual_address.value != 0;
}

pub fn access(virtual_address: VirtualAddress, comptime Ptr: type) Ptr {
    return @intToPtr(Ptr, virtual_address.value);
}

pub inline fn identity_physical_address(virtual_address: VirtualAddress) PhysicalAddress {
    return PhysicalAddress.new(virtual_address.value);
}

pub inline fn offset(virtual_address: VirtualAddress, asked_offset: u64) VirtualAddress {
    return VirtualAddress.new(virtual_address.value + asked_offset);
}

pub inline fn aligned_forward(virtual_address: VirtualAddress, alignment: u64) VirtualAddress {
    return VirtualAddress{ .value = common.align_forward(virtual_address.value, alignment) };
}

pub inline fn aligned_backward(virtual_address: VirtualAddress, alignment: u64) VirtualAddress {
    return VirtualAddress{ .value = common.align_backward(virtual_address.value, alignment) };
}

pub inline fn align_forward(virtual_address: *VirtualAddress, alignment: u64) void {
    virtual_address.* = virtual_address.aligned_forward(alignment);
}

pub inline fn align_backward(virtual_address: *VirtualAddress, alignment: u64) void {
    virtual_address.* = virtual_address.aligned_backward(alignment);
}

pub inline fn is_higher_half(virtual_address: VirtualAddress) bool {
    return virtual_address.value >= 0xffff_8000_0000_000;
}
