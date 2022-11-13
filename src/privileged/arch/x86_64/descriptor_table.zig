const common = @import("common");
const assert = common.assert;

pub const Register = extern struct {
    limit: u16,
    address: u64 align(2),

    comptime {
        assert(@sizeOf(Register) == 10);
    }
};
