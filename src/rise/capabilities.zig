const lib = @import("lib");
const assert = lib.assert;

const rise = @import("rise");
const syscall = rise.syscall;

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

inline fn err(comptime thing_name: []const u8, something: anytype) void {
    @compileError(thing_name ++ " not implemented for " ++ switch (@TypeOf(something)) {
        Type => "capability ",
        else => "command ",
    } ++ @tagName(something));
}

pub fn ErrorSet(comptime capability: Type, comptime command: capability.toCommand()) type {
    return switch (capability) {
        .io => switch (command) {
            .log => lib.ErrorSet(.{}),
            else => err("Error", command),
        },
        .cpu => switch (command) {
            .get_core_id => lib.ErrorSet(.{}),
            .shutdown => lib.ErrorSet(.{}),
        },
        else => err("Error", capability),
    };
}

pub fn Result(comptime capability: Type, comptime command: capability.toCommand()) type {
    return switch (capability) {
        .io => switch (command) {
            .log => usize,
            else => err("Result", command),
        },
        .cpu => switch (command) {
            .get_core_id => u32,
            .shutdown => noreturn,
        },
        else => err("Result", capability),
    };
}

pub fn Arguments(comptime capability: Type, comptime command: capability.toCommand()) type {
    return switch (capability) {
        .io => switch (command) {
            .log => []const u8,
            else => err("Arguments", command),
        },
        .cpu => switch (command) {
            .get_core_id => void,
            .shutdown => void,
        },
        else => err("Arguments", capability),
    };
}

pub fn toResult(raw_result: syscall.Result.Rise, comptime capability: Type, comptime command: capability.toCommand()) Result(capability, command) {
    return switch (capability) {
        .io => switch (command) {
            .log => raw_result.second,
            else => err("Arguments", command),
        },
        .cpu => switch (command) {
            .get_core_id => @intCast(u32, raw_result.second),
            .shutdown => @compileError("No result is expected from shutdown"),
        },
        else => err("toResult", capability),
    };
}
