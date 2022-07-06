const PhysicalAddress = @This();

const common = @import("../common.zig");
const configuration = @import("configuration");
const TODO = common.TODO;

const VirtualAddress = common.VirtualAddress;
const log = common.log.scoped(.PhysicalAddress);

value: u64,

pub inline fn new(value: u64) PhysicalAddress {
    const physical_address = PhysicalAddress{
        .value = value,
    };

    if (!physical_address.is_valid()) {
        common.panic(@src(), "physical address 0x{x} is invalid", .{physical_address.value});
    }

    return physical_address;
}

pub inline fn temporary_invalid() PhysicalAddress {
    return maybe_invalid(0);
}

pub inline fn maybe_invalid(value: u64) PhysicalAddress {
    return PhysicalAddress{
        .value = value,
    };
}

pub inline fn is_valid(physical_address: PhysicalAddress) bool {
    common.runtime_assert(@src(), physical_address.value != 0);
    common.runtime_assert(@src(), configuration.max_physical_address_bit != 0);
    const max = @as(u64, 1) << configuration.max_physical_address_bit;
    common.runtime_assert(@src(), max > common.max_int(u32));
    //log.debug("Physical address 0x{x} validation in the kernel: {}. Max bit: {}. Maximum physical address: 0x{x}", .{ physical_address.value, is_kernel, cpu_features.physical_address_max_bit, max });
    return physical_address.value <= max;
}

pub inline fn is_equal(physical_address: PhysicalAddress, other: PhysicalAddress) bool {
    return physical_address.value == other.value;
}

pub inline fn belongs_to_region(physical_address: PhysicalAddress, region: common.PhysicalMemoryRegion) bool {
    return physical_address.value >= region.address.value and physical_address.value < region.address.value + region.size;
}

pub inline fn offset(physical_address: PhysicalAddress, asked_offset: u64) PhysicalAddress {
    return PhysicalAddress.new(physical_address.value + asked_offset);
}

/// This would return the correct address even before initializing the higher half and mapping. This would only fail if it's used with the kernel memory-mapped regions before setting up paging and higher-half
pub inline fn access_kernel(physical_address: PhysicalAddress, comptime Ptr: type) Ptr {
    const root = @import("root");
    comptime common.comptime_assert(root.privilege_level != .user);
    return physical_address.access_higher_half(Ptr);
}

pub inline fn to_higher_half_virtual_address(physical_address: PhysicalAddress) VirtualAddress {
    const root = @import("root");
    comptime common.comptime_assert(root.privilege_level != .user);
    var higher_half: u64 = 0;
    if (@hasDecl(root, "higher_half_direct_map")) {
        higher_half = root.higher_half_direct_map.value;
    }
    const address = VirtualAddress.new(physical_address.value + higher_half);
    return address;
}

pub inline fn to_virtual_address_with_offset(physical_address: PhysicalAddress, asked_offset: u64) VirtualAddress {
    return VirtualAddress.new(physical_address.value + asked_offset);
}

inline fn access_higher_half(physical_address: PhysicalAddress, comptime Ptr: type) Ptr {
    const address = physical_address.to_higher_half_virtual_address().value;
    return @intToPtr(Ptr, address);
}

pub inline fn aligned_forward(virtual_address: PhysicalAddress, alignment: u64) PhysicalAddress {
    return PhysicalAddress{ .value = common.align_forward(virtual_address.value, alignment) };
}

pub inline fn aligned_backward(virtual_address: PhysicalAddress, alignment: u64) PhysicalAddress {
    return PhysicalAddress{ .value = common.align_backward(virtual_address.value, alignment) };
}

pub inline fn align_forward(virtual_address: *VirtualAddress, alignment: u64) void {
    virtual_address.* = virtual_address.aligned_forward(alignment);
}

pub inline fn align_backward(virtual_address: *VirtualAddress, alignment: u64) void {
    virtual_address.* = virtual_address.aligned_backward(alignment);
}
