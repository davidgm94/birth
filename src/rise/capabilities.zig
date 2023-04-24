const lib = @import("lib");
const assert = lib.assert;

pub const Type = enum(u1) {
    cpu,
    io,
    // _,

    pub const Type = u8;
};

pub const Subtype = u16;
pub const AllTypes = Type;
pub const cpu = enum(u1) {
    shutdown,
    get_core_id,
};
pub const io = enum(u1) {
    stdout,
    _,
};
