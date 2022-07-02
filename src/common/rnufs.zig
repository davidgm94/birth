//! This is not an official USTAR implementation, but my own custom version just to get started with
pub const Node = struct {
    name: [100]u8,
    parent: [100]u8,
    size: u64,
    last_modification: u64,
    type: NodeType,
};

pub const NodeType = enum(u64) {
    file,
    directory,
};

pub const sector_size = 0x200;
