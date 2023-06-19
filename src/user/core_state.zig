const user = @import("user");
const VirtualAddressSpace = user.VirtualAddressSpace;

pub const PagingState = extern struct {
    virtual_address_space: VirtualAddressSpace,
    physical_map: user.PhysicalMap,
};

pub const CoreState = extern struct {
    paging_state: PagingState,
};
