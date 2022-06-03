const kernel = @import("kernel.zig");
const Virtual = kernel.Virtual;
const Physical = kernel.Physical;

pub const Region = struct {
    address: Virtual.Address,
    size: u64,

    pub fn map(region: Region, address_space: *Virtual.AddressSpace, base_physical_address: Physical.Address) void {
        var physical_address = base_physical_address;
        var virtual_address = region.address;
        var size_it: u64 = 0;
        while (size_it < region.size) : (size_it += kernel.arch.page_size) {
            address_space.arch.map(physical_address, virtual_address);
            physical_address.page_up();
            virtual_address.page_up();
        }
    }
};

pub const RegionWithPermissions = struct {
    descriptor: Region,
    read: bool,
    write: bool,
    execute: bool,
};
