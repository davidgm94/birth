pub const Region = struct {
    descriptor: Descriptor,
    bitset: []u8,
    allocated_page_count: u64,

    pub const Descriptor = struct {
        address: u64,
        size: u64,
    };
};
