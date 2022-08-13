const std = @import("../common/std.zig");
const arch = @import("arch.zig");

pub const page_size = arch.valid_page_sizes[0];
comptime {
    std.comptime_assert(page_size == 0x1000);
}
pub const page_shifter = @ctz(u64, page_size);

pub var max_physical_address_bit: u6 = 0;
