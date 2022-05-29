const kernel = @import("../../kernel.zig");

pub const Descriptor = packed struct {
    limit_low: u16,
    base_low: u16,
    base_mid_low: u8,
    access_byte: u8,
    limit_high: u4,
    flags: u4,
    base_mid_high: u8,
    base_high: u32,
    reserved: u32 = 0,

    comptime {
        kernel.assert_unsafe(@sizeOf(Descriptor) == 16);
    }
};
