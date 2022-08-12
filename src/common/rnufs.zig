//! This is a custom variation of the USTAR filesystem just to get started with
pub const Node = struct {
    name: [100]u8,
    parent: [100]u8,
    size: u64,
    last_modification: u64,
    type: NodeType,
};

pub const NodeType = enum(u64) {
    empty = 0,
    file = 1,
    directory = 2,
};

pub const sector_size = 0x200;
