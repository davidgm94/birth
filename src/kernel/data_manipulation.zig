const std = @import("std");
pub inline fn string_eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

pub inline fn string_starts_with(str: []const u8, slice: []const u8) bool {
    return std.mem.startsWith(u8, str, slice);
}

pub inline fn string_ends_with(str: []const u8, slice: []const u8) bool {
    return std.mem.endsWith(u8, str, slice);
}

pub inline fn align_forward(n: u64, alignment: u64) u64 {
    const mask: u64 = alignment - 1;
    const result = (n + mask) & ~mask;
    return result;
}

pub inline fn read_int_big(comptime T: type, slice: []const u8) T {
    return std.mem.readIntBig(T, slice[0..@sizeOf(T)]);
}

pub const copy = std.mem.copy;
