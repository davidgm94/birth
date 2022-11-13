pub const Type = enum(u32) {
    rise = 0,
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
