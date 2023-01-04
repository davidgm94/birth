const common = @import("../lib.zig");
pub const FAT32 = @import("filesystem/fat32.zig");

pub const Type = common.FilesystemType;

pub const ReadError = error{
    unsupported,
    failed,
};

pub const WriteError = error{
    unsupported,
    failed,
};

test {
    _ = FAT32;
}
