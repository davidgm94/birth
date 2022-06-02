const kernel = @import("kernel.zig");
const PhysicalAddress = @This();
value: u64,

pub inline fn new(value: u64) PhysicalAddress {
    const physical_address = PhysicalAddress{
        .value = value,
    };

    if (!physical_address.is_valid()) {
        kernel.panic("physical address 0x{x} is invalid", .{physical_address.value});
    }

    return physical_address;
}

pub inline fn is_valid(physical_address: PhysicalAddress) bool {
    return kernel.arch.is_valid_physical_address(physical_address.value);
}
