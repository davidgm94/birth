const lib = @import("lib");
const x86 = @import("x86/common.zig");
pub usingnamespace x86;

pub const valid_page_sizes = [3]comptime_int{ 0x1000, 0x1000 * 0x200, 0x1000 * 0x200 * 0x200 };
pub const reverse_valid_page_sizes = blk: {
    var reverse = valid_page_sizes;
    lib.reverse(@TypeOf(valid_page_sizes[0]), &reverse);
    // var reverse_u64: [valid_page_sizes.len]u64 = undefined;
    // for (reverse, &reverse_u64) |r_el, *ru64_el| {
    //     ru64_el.* = r_el;
    // }

    break :blk reverse;
};
pub const default_page_size = valid_page_sizes[0];
pub const reasonable_page_size = valid_page_sizes[1];

pub const registers = @import("x86/64/registers.zig");

pub inline fn readTimestamp() u64 {
    var edx: u32 = undefined;
    var eax: u32 = undefined;

    asm volatile (
        \\rdtsc
        : [eax] "={eax}" (eax),
          [edx] "={edx}" (edx),
    );

    return @as(u64, edx) << 32 | eax;
}

pub const stack_alignment = 0x10;
