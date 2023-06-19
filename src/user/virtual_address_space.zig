const lib = @import("lib");
const log = lib.log;

const user = @import("user");
const PhysicalMap = user.PhysicalMap;
const PhysicalMemoryRegion = user.PhysicalMemoryRegion;
const VirtualMemoryRegion = user.VirtualMemoryRegion;

pub const MMUAwareVirtualAddressSpace = @import("mmu_aware_virtual_address_space.zig").MMUAwareVirtualAddressSpace;

pub const VirtualAddressSpace = extern struct {
    physical_map: *PhysicalMap,
    // TODO: layout
    regions: ?*VirtualMemoryRegion = null,

    /// The function is inlined because it's only called once
    pub inline fn initializeCurrent() !void {
        log.debug("VirtualAddressSpace.initializeCurrent", .{});
        const virtual_address_space = user.process.getVirtualAddressSpace();
        const physical_map = user.process.getPhysicalMap();
        virtual_address_space.physical_map = physical_map;

        const root_page_level = 0;
        physical_map.* = try PhysicalMap.init(virtual_address_space, root_page_level, user.process.getSlotAllocator());
        // This should be an inline call as this the only time this function is called
        try physical_map.initializeCurrent();

        try virtual_address_space.pinnedInit();

        log.warn("TODO: VirtualAddressSpace.initializeCurrent is incomplete!", .{});
    }

    pub inline fn pinnedInit(virtual_address_space: *VirtualAddressSpace) !void {
        const pinned_state = user.process.getPinnedState();
        const pinned_size = 128 * lib.mb;
        pinned_state.physical_memory_region = try PhysicalMemoryRegion.Pinned.new(pinned_size);

        pinned_state.virtual_memory_region = try virtual_address_space.map(pinned_state.physical_memory_region.getGeneric().*, 0, pinned_size, .{ .write = true });
        log.warn("TODO: VirtualAddressSpace.pinnedInit", .{});
    }

    pub inline fn map(virtual_address_space: *VirtualAddressSpace, physical_memory_region: PhysicalMemoryRegion, offset: usize, size: usize, flags: VirtualMemoryRegion.Flags) !VirtualMemoryRegion {
        const alignment = lib.arch.valid_page_sizes[0];
        return virtual_address_space.mapAligned(physical_memory_region, offset, size, alignment, flags);
    }

    pub fn mapAligned(virtual_address_space: *VirtualAddressSpace, physical_memory_region: PhysicalMemoryRegion, offset: usize, size: usize, alignment: usize, flags: VirtualMemoryRegion.Flags) !VirtualMemoryRegion {
        const virtual_address = try virtual_address_space.physical_map.determineAddress(physical_memory_region, alignment);
        _ = virtual_address;
        _ = offset;
        _ = size;
        _ = flags;
        @panic("TODO: VirtualAddressSpace.mapAligned");
    }

    pub const State = extern struct {
        virtual_address_space: VirtualAddressSpace,
        physical_map: PhysicalMap,
    };
};
