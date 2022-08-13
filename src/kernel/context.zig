const std = @import("../common/std.zig");

pub const page_size = common.valid_page_sizes[0];
comptime {
    std.assert(page_size == 0x1000);
}
pub const page_shifter = @ctz(u64, page_size);
pub var max_physical_address_bit: u6 = 0;

const common = @import("arch/common.zig");

pub usingnamespace common;
