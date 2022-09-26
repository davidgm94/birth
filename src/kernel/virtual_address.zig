const VirtualAddress = @This();

const common = @import("common");
const assert = common.assert;

const RNU = @import("RNU");
const PhysicalAddress = RNU.PhysicalAddress;

value: u64,

pub inline fn new(value: u64) VirtualAddress {
    const virtual_address = VirtualAddress{
        .value = value,
    };
    assert(virtual_address.is_valid());
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

pub fn format(virtual_address: VirtualAddress, comptime _: []const u8, _: common.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
    try common.internal_format(writer, "0x{x}", .{virtual_address.value});
}
