const kernel = @import("kernel.zig");
const Virtual = @This();
const Physical = kernel.Physical;
const log = kernel.log.scoped(.Virtual);
pub const Memory = @import("virtual_memory.zig");
pub const Address = @import("virtual_address.zig");

pub const AddressSpace = struct {
    arch: kernel.arch.AddressSpace,
    free_regions_by_address: kernel.AVL.Tree(Virtual.Memory.Region),
    free_regions_by_size: kernel.AVL.Tree(Virtual.Memory.Region),
    used_regions: kernel.AVL.Tree(Virtual.Memory.Region),

    pub inline fn new(context: anytype) AddressSpace {
        return AddressSpace{
            .arch = kernel.arch.AddressSpace.new(context),
            .free_regions_by_address = kernel.AVL.Tree(Virtual.Memory.Region){},
            .free_regions_by_size = kernel.AVL.Tree(Virtual.Memory.Region){},
            .used_regions = kernel.AVL.Tree(Virtual.Memory.Region){},
        };
    }

    //pub inline fn allocate(address_space: *AddressSpace) void {
    //}

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

    const IntegrationError = error{
        region_allocation_failed,
    };

    pub fn integrate_mapped_physical_entry(address_space: *AddressSpace, entry: kernel.Physical.Memory.Map.Entry, base_virtual_address: Virtual.Address) !void {
        kernel.assert(@src(), entry.descriptor.size != 0);
        log.debug("region size: {}", .{entry.descriptor.size});

        if (entry.descriptor.size != entry.allocated_size) {
            const free_region_offset = base_virtual_address.value + entry.allocated_size;
            const free_region_size = entry.descriptor.size - entry.allocated_size;
            const free_region = kernel.core_heap.allocate(Virtual.Memory.Region) orelse return IntegrationError.region_allocation_failed;
            free_region.* = Virtual.Memory.Region.new(Virtual.Address.new(free_region_offset), free_region_size);
            log.debug("Free region: (0x{x}, {})", .{ free_region.address.value, free_region.size });

            var result = address_space.free_regions_by_address.insert(&free_region.item_address, free_region, free_region.address.value, .panic);
            kernel.assert(@src(), result);
            result = address_space.free_regions_by_size.insert(&free_region.item_size, free_region, free_region.size, .allow);
            kernel.assert(@src(), result);
        }

        if (entry.allocated_size != 0) {
            const used_region = kernel.core_heap.allocate(Virtual.Memory.Region) orelse return IntegrationError.region_allocation_failed;
            used_region.* = Virtual.Memory.Region.new(base_virtual_address, entry.allocated_size);
            used_region.used = true;
            log.debug("Used region: (0x{x}, {})", .{ used_region.address.value, used_region.size });

            kernel.assert(@src(), used_region.address.value != 0);
            const result = address_space.used_regions.insert(&used_region.item_address, used_region, used_region.address.value, .panic);
            kernel.assert(@src(), result);
        }
    }

    pub fn integrate_mapped_physical_region(address_space: *AddressSpace, region: kernel.Physical.Memory.Region, base_virtual_address: Virtual.Address) !void {
        kernel.assert(@src(), region.size != 0);
        log.debug("region size: {}", .{region.size});

        const used_region = kernel.core_heap.allocate(Virtual.Memory.Region) orelse return IntegrationError.region_allocation_failed;
        used_region.* = Virtual.Memory.Region.new(base_virtual_address, region.size);
        used_region.used = true;
        log.debug("Used region: (0x{x}, {})", .{ used_region.address.value, used_region.size });

        kernel.assert(@src(), used_region.address.value != 0);
        const result = address_space.used_regions.insert(&used_region.item_address, used_region, used_region.address.value, .panic);
        kernel.assert(@src(), result);
    }
};
