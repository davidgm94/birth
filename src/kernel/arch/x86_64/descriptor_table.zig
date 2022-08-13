const std = @import("../../../common/std.zig");

pub const Register = packed struct {
    limit: u16,
    address: u64,

    comptime {
        std.assert(@sizeOf(Register) == 10);
    }
};
