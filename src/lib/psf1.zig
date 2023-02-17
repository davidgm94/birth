const lib = @import("lib");

pub const Header = extern struct {
    magic: [2]u8,
    mode: u8,
    character_size: u8,

    pub const magic = .{ 0x36, 0x04 };
};

pub const Error = error{
    invalid_magic,
};
