const std = @import("std");
const kernel = @import("../kernel.zig");

pub const assert_unsafe = std.debug.assert;
pub fn assert(src: std.builtin.SourceLocation, condition: bool) void {
    if (!condition) kernel.panic("Assert failed at {s}:{}:{} {s}()\n", .{ src.file, src.line, src.column, src.fn_name });
}
