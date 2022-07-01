const common = @import("../../../common.zig");

pub const Register = packed struct {
    limit: u16,
    address: u64,

    comptime {
        common.comptime_assert(@sizeOf(Register) == 10);
    }
};
