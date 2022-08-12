pub const Type = enum {
    qemu,
    virtualbox,
    vmware,
    bochs,
};

pub const ExitStatus = enum(u32) {
    success = 0,
    failure = 1,
};
