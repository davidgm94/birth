const user = @import("user");
const currentScheduler = user.currentScheduler;
const MoreCore = user.MoreCore;
const PhysicalMap = user.PhysicalMap;
const PinnedState = user.PinnedState;
const SlotAllocator = user.SlotAllocator;
const VirtualAddressSpace = user.VirtualAddressSpace;

pub inline fn getVirtualAddressSpace() *VirtualAddressSpace {
    return &currentScheduler().core_state.paging.virtual_address_space;
}

pub inline fn getPhysicalMap() *PhysicalMap {
    return &currentScheduler().core_state.paging.physical_map;
}

pub inline fn getSlotAllocatorState() *SlotAllocator.State {
    return &currentScheduler().core_state.slot_allocator;
}

pub inline fn getSlotAllocator() *SlotAllocator {
    return &currentScheduler().core_state.slot_allocator.default_allocator.allocator;
}

pub inline fn getPinnedState() *PinnedState {
    return &currentScheduler().core_state.pinned;
}

pub inline fn getMoreCoreState() *MoreCore.State {
    return &currentScheduler().core_state.more_core;
}
