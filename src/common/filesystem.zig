const common = @import("../common.zig");
pub const FAT32 = @import("filesystem/fat32.zig");

pub const Type = enum(u32) {
    rise = 0,
    ext2 = 1,
    fat32 = 2,

    pub const count = common.enum_count(@This());
};

pub const ReadError = error{
    unsupported,
    failed,
};

pub const WriteError = error{
    unsupported,
    failed,
};
