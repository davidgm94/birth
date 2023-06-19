const user = @import("user");

pub inline fn getVirtualAddressSpace() *user.VirtualAddressSpace {
    return &user.currentScheduler().core_state.paging_state.virtual_address_space;
}

pub inline fn getPhysicalMap() *user.PhysicalMap {
    return &user.currentScheduler().core_state.paging_state.physical_map;
}
