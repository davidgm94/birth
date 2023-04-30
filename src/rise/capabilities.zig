const lib = @import("lib");
const assert = lib.assert;

pub const Type = enum(u8) {
    io,
    irq_table,
    cpu,
    physical_memory,
    // Inherited from physical memory
    device_memory,
    ram,
    // Inherited from RAM
    cpu_memory,
    vnode,
    scheduler,

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

// Slots
