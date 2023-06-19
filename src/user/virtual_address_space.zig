const user = @import("user");
const PhysicalMap = user.PhysicalMap;
const VirtualMemoryRegion = user.VirtualMemoryRegion;

pub const MMUAwareVirtualAddressSpace = @import("mmu_aware_virtual_address_space.zig").MMUAwareVirtualAddressSpace;

pub const VirtualAddressSpace = extern struct {
    physical_map: *PhysicalMap,
    // TODO: layout
    regions: ?*VirtualMemoryRegion = null,
};
