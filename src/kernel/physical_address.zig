const PhysicalAddress = @This();

const std = @import("../common/std.zig");

const arch = @import("arch/common.zig");
const crash = @import("crash.zig");
const kernel = @import("kernel.zig");
const PhysicalMemoryRegion = @import("physical_memory_region.zig");
const VirtualAddress = @import("virtual_address.zig");

const TODO = crash.TODO;
const panic = crash.panic;
const log = std.log.scoped(.PhysicalAddress);

value: u64,

pub inline fn new(value: u64) PhysicalAddress {
    const physical_address = PhysicalAddress{
        .value = value,
    };

    if (!physical_address.is_valid()) {
        panic("physical address 0x{x} is invalid", .{physical_address.value});
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
    std.assert(physical_address.value != 0);
    std.assert(arch.max_physical_address_bit != 0);
    const max = @as(u64, 1) << arch.max_physical_address_bit;
    std.assert(max > std.max_int(u32));
    //log.debug("Physical address 0x{x} validation in the kernel: {}. Max bit: {}. Maximum physical address: 0x{x}", .{ physical_address.value, is_kernel, cpu_features.physical_address_max_bit, max });
    return physical_address.value <= max;
}

pub inline fn is_equal(physical_address: PhysicalAddress, other: PhysicalAddress) bool {
    return physical_address.value == other.value;
}

pub inline fn belongs_to_region(physical_address: PhysicalAddress, region: PhysicalMemoryRegion) bool {
    return physical_address.value >= region.address.value and physical_address.value < region.address.value + region.size;
}

pub inline fn offset(physical_address: PhysicalAddress, asked_offset: u64) PhysicalAddress {
    return PhysicalAddress.new(physical_address.value + asked_offset);
}

pub inline fn to_identity_mapped_virtual_address(physical_address: PhysicalAddress) VirtualAddress {
    log.warn("Warning: using unsafe method to_identity_mapped_virtual_address", .{});
    return VirtualAddress.new(physical_address.value);
}

pub inline fn to_higher_half_virtual_address(physical_address: PhysicalAddress) VirtualAddress {
    const higher_half = kernel.higher_half_direct_map.value;
    if (higher_half == 0) @panic("wtf");
    log.warn("Warning: using unsafe method to_higher_half_virtual_address", .{});
    const address = VirtualAddress.new(physical_address.value + higher_half);
    return address;
}

pub inline fn to_virtual_address_with_offset(physical_address: PhysicalAddress, asked_offset: u64) VirtualAddress {
    return VirtualAddress.new(physical_address.value + asked_offset);
}

pub inline fn aligned_forward(virtual_address: PhysicalAddress, alignment: u64) PhysicalAddress {
    return PhysicalAddress{ .value = std.align_forward(virtual_address.value, alignment) };
}

pub inline fn aligned_backward(virtual_address: PhysicalAddress, alignment: u64) PhysicalAddress {
    return PhysicalAddress{ .value = std.align_backward(virtual_address.value, alignment) };
}

pub inline fn align_forward(virtual_address: *VirtualAddress, alignment: u64) void {
    virtual_address.* = virtual_address.aligned_forward(alignment);
}

pub inline fn align_backward(virtual_address: *VirtualAddress, alignment: u64) void {
    virtual_address.* = virtual_address.aligned_backward(alignment);
}

pub fn format(physical_address: PhysicalAddress, comptime _: []const u8, _: std.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
    try std.internal_format(writer, "0x{x}", .{physical_address.value});
}
