const lib = @import("lib");
const assert = lib.assert;

pub const Type = enum(DataType) {
    cpu,
    io,
    _,
    pub const DataType = u8;
};

pub const Command = struct {
    pub const DataType = u16;

    pub const CPU = enum(DataType) {
        shutdown,
        get_core_id,
        _,
    };

    pub const IO = enum(DataType) {
        stdout,
        _,
    };

    pub fn Generic(comptime capability_type: Type) type {
        const command_type = switch (capability_type) {
            .cpu => CPU,
            .io => IO,
            _ => @compileError("Unreachable"),
            //else => @compileError("Not implemented"),
        };

        assert(@sizeOf(command_type) == @sizeOf(Command.DataType));

        return command_type;
    }
};
