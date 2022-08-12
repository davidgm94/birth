// This is only a definition file. Imports are forbidden

pub const DiskDriverType = enum(u32) {
    virtio = 0,
    nvme = 1,
    ahci = 2,
    ide = 3,
    memory = 4,
};

pub const FilesystemDriverType = enum(u32) {
    RNU = 0,
    ext2 = 1,
};
