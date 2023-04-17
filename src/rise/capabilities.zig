const lib = @import("lib");
const assert = lib.assert;

pub const Type = enum(DataType) {
    cpu,
    _,
    pub const DataType = u8;
};

pub const Command = struct {
    pub const DataType = u16;

    pub const CPU = enum(DataType) {
        shutdown,
    };

    pub fn Generic(comptime capability_type: Type) type {
        const command_type = switch (capability_type) {
            .cpu => CPU,
            else => @compileError("Not implemented"),
        };

        assert(@sizeOf(command_type) == @sizeOf(Command.DataType));

        return command_type;
    }
};

pub fn Arguments(comptime capability_type: Type, comptime command: Command.Generic(capability_type)) type {
    _ = command;
    return switch (capability_type) {
        .cpu => void,
        _ => @compileError("Not implemented"),
    };
}
