const lib = @import("lib");
const assert = lib.assert;

const Capabilities = @This();

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

    pub fn toCommand(comptime capability_type: Capabilities.Type) type {
        return @field(Capabilities, @tagName(capability_type));
    }
};

pub const Subtype = u16;
pub const AllTypes = Type;
pub const cpu = enum(u1) {
    shutdown,
    get_core_id,
};
pub const io = enum(u1) {
    log,
    _,
};
pub const irq_table = enum(u1) {
    _,
};
pub const physical_memory = enum(u1) {
    _,
};
pub const device_memory = enum(u1) {
    _,
};
pub const ram = enum(u1) {
    _,
};
pub const cpu_memory = enum(u1) {
    _,
};
pub const vnode = enum(u1) {
    _,
};
pub const scheduler = enum(u1) {
    _,
};

pub const CommandMap = blk: {
    var command_map: [lib.enumCount(Type)]type = undefined;
    command_map[@enumToInt(Type.io)] = io;
    command_map[@enumToInt(Type.cpu)] = cpu;

    break :blk command_map;
};

// Slots
