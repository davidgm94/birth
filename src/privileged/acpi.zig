pub const RSDP = extern struct {
    pub const Descriptor1 = extern struct {
        signature: [8]u8,
        checksum: u8,
        OEM_ID: [6]u8,
        revision: u8,
        RSDT_address: u32,
    };

    pub const Descriptor2 = extern struct {
        descriptor1: Descriptor1,
        length: u32,
        XSDT_address: u64,
        extended_checksum: u8,
        reserved: [3]u8,
    };
};
