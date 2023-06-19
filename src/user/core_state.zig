const user = @import("user");
const MoreCore = user.MoreCore;
const PhysicalMap = user.PhysicalMap;
const PhysicalMemoryRegion = user.PhysicalMemoryRegion;
const SlotAllocator = user.SlotAllocator;
const VirtualAddressSpace = user.VirtualAddressSpace;
const VirtualMemoryRegion = user.VirtualMemoryRegion;

pub const PagingState = extern struct {
    virtual_address_space: VirtualAddressSpace,
    physical_map: PhysicalMap,
};

pub const PinnedState = extern struct {
    physical_memory_region: PhysicalMemoryRegion.Pinned,
    virtual_memory_region: VirtualMemoryRegion,
    offset: usize,
    // TODO: lists
};

pub const CoreState = extern struct {
    paging: PagingState,
    slot_allocator: SlotAllocator.State,
    virtual_address_space: VirtualAddressSpace.State,
    pinned: PinnedState,
    more_core: MoreCore.State,
};
