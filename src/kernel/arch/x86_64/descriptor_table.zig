const kernel = @import("kernel");
pub const Register = packed struct {
    limit: u16,
    address: u64,

    comptime {
        kernel.assert_unsafe(@sizeOf(Register) == 10);
    }
};
