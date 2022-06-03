const kernel = @import("kernel.zig");
const Virtual = @This();
const Physical = kernel.Physical;
pub const Memory = @import("virtual_memory.zig");
pub const Address = @import("virtual_address.zig");

pub const AddressSpace = struct {
    arch: kernel.arch.AddressSpace,

    pub inline fn new(context: anytype) AddressSpace {
        return AddressSpace{
            .arch = kernel.arch.AddressSpace.new(context),
        };
    }

    pub inline fn translate_address(address_space: *AddressSpace, virtual_address: Virtual.Address) ?Physical.Address {
        return address_space.arch.translate_address(virtual_address);
    }

    pub inline fn map(address_space: *AddressSpace, physical_address: Physical.Address, virtual_address: Virtual.Address) void {
        address_space.arch.map(physical_address, virtual_address);
        const checked_physical_address = address_space.translate_address(virtual_address) orelse @panic("mapping failed");
        kernel.assert(@src(), checked_physical_address.value == physical_address.value);
    }

    pub inline fn make_current(address_space: *AddressSpace) void {
        address_space.arch.make_current();
    }
};
