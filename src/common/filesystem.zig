pub const Type = enum(u32) {
    RNU = 0,
    ext2 = 1,
};

pub const ReadError = error{
    unsupported,
    failed,
};

pub const WriteError = error{
    unsupported,
    failed,
};
