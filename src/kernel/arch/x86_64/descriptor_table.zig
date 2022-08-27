const std = @import("../../../common/std.zig");

pub const Register = extern struct {
    limit: u16,
    address: u64 align(2),

    comptime {
        std.assert(@sizeOf(Register) == 10);
    }
};
