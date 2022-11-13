const common = @import("common");

pub const valid_page_sizes = [3]comptime_int{ 0x1000, 0x1000 * 0x200, 0x1000 * 0x200 * 0x200 };
pub const reverse_valid_page_sizes = blk: {
    var reverse = valid_page_sizes;
    common.std.mem.reverse(@TypeOf(valid_page_sizes[0]), &reverse);
    break :blk reverse;
};
pub const page_size = valid_page_sizes[0];
pub const reasonable_page_size = valid_page_sizes[1];

pub fn page_shifter(comptime asked_page_size: comptime_int) comptime_int {
    return @ctz(@as(u32, asked_page_size));
}

pub const registers = @import("x86_64/registers.zig");
