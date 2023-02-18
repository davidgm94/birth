const lib = @import("lib");
pub const FAT32 = @import("filesystem/fat32.zig");

pub const Type = lib.FilesystemType;

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
