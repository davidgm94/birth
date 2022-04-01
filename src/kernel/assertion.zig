const std = @import("std");
const kernel = @import("kernel.zig");

pub const assert_unsafe = std.debug.assert;
pub inline fn assert(src: std.builtin.SourceLocation, condition: bool) void {
    if (!condition) kernel.panic("Assertion failed at {}\n", .{src});
}
