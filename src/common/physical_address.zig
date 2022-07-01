const PhysicalAddress = @This();

const common = @import("../common.zig");
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
    const root = @import("root");
    const is_kernel = @hasDecl(root, "cpu_features");
    if (is_kernel) {
        const cpu_features = root.cpu_features;
        common.runtime_assert(@src(), physical_address.value != 0);
        common.runtime_assert(@src(), cpu_features.physical_address_max_bit != 0);
        const max = @as(u64, 1) << cpu_features.physical_address_max_bit;
        common.runtime_assert(@src(), max > 1000);
        log.debug("Physical address 0x{x} validation in the kernel: {}. Max bit: {}. Maximum physical address: 0x{x}", .{ physical_address.value, is_kernel, cpu_features.physical_address_max_bit, max });
        return physical_address.value <= max;
    } else {
        TODO(@src());
    }
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

pub inline fn identity_virtual_address(physical_address: PhysicalAddress) VirtualAddress {
    return physical_address.identity_virtual_address_extended(false);
}

pub inline fn identity_virtual_address_extended(physical_address: PhysicalAddress, comptime override: bool) VirtualAddress {
    const root = @import("root");
    if (@hasDecl(root, "Virtual")) {
        if (!override and root.Virtual.initialized) common.TODO(@src());
    }
    return VirtualAddress.new(physical_address.value);
}

pub inline fn access_identity(physical_address: PhysicalAddress, comptime Ptr: type) Ptr {
    //const root = @import("root");
    //if (@hasDecl(root, "Virtual")) {
    //common.runtime_assert(@src(), !root.Virtual.initialized);
    //}

    return @intToPtr(Ptr, identity_virtual_address(physical_address).value);
}

pub inline fn access(physical_address: PhysicalAddress, comptime Ptr: type) Ptr {
    _ = Ptr;
    _ = physical_address;
    TODO(@src());
    //const root = @import("root");
    //const initialized_virtual = @hasDecl(root, "Virtual") and root.Virtual.initialized;
    //return if (initialized_virtual) physical_address.access_higher_half(Ptr) else physical_address.access_identity(Ptr);
}

pub inline fn to_higher_half_virtual_address(physical_address: PhysicalAddress) VirtualAddress {
    const root = @import("root");
    var higher_half: u64 = 0;
    if (@hasDecl(root, "higher_half_direct_map")) {
        higher_half = root.higher_half_direct_map.value;
    }
    log.debug("Using higher half address 0x{x} for physical address 0x{x}", .{ higher_half, physical_address.value });
    return VirtualAddress.new(physical_address.value + higher_half);
}

pub inline fn access_higher_half(physical_address: PhysicalAddress, comptime Ptr: type) Ptr {
    return @intToPtr(Ptr, physical_address.to_higher_half_virtual_address().value);
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
