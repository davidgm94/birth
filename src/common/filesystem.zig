pub const FAT32 = @import("filesystem/fat32.zig");

pub const Type = enum(u32) {
    rise = 0,
    ext2 = 1,
    fat32 = 2,
};

pub const ReadError = error{
    unsupported,
    failed,
};

pub const WriteError = error{
    unsupported,
    failed,
};
