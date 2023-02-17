const lib = @import("lib");
const assert = lib.assert;

pub const Register = extern struct {
    limit: u16,
    address: u64 align(2),

    comptime {
        assert(@sizeOf(Register) == 10);
    }
};
