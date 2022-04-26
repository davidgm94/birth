const std = @import("std");
const kernel = @import("kernel.zig");
const page_size = kernel.arch.page_size;
const sector_size = kernel.arch.sector_size;
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

pub inline fn align_backward(n: u64, alignment: u64) u64 {
    return n & ~(alignment - 1);
}

pub inline fn is_aligned(n: u64, alignment: u64) bool {
    return n & (alignment - 1) == 0;
}

pub inline fn read_int_big(comptime T: type, slice: []const u8) T {
    return std.mem.readIntBig(T, slice[0..@sizeOf(T)]);
}

pub const copy = std.mem.copy;

pub inline fn zero(bytes: []u8) void {
    for (bytes) |*byte| byte.* = 0;
}

pub inline fn zeroes(comptime T: type) T {
    var result: T = undefined;
    zero(@ptrCast([*]u8, &result)[0..@sizeOf(T)]);
    return result;
}

pub inline fn zero_a_page(page_address: u64) void {
    kernel.assert(@src(), is_aligned(page_address, kernel.arch.page_size));
    zero(@intToPtr([*]u8, page_address)[0..kernel.arch.page_size]);
}

pub inline fn bytes_to_pages(bytes: u64) u64 {
    const pages = (bytes / page_size) + @boolToInt(bytes % page_size != 0);
    return pages;
}

pub inline fn bytes_to_sector(bytes: u64) u64 {
    const pages = (bytes / sector_size) + @boolToInt(bytes % sector_size != 0);
    return pages;
}

pub const maxInt = std.math.maxInt;

pub const as_bytes = std.mem.asBytes;

pub const spinloop_hint = std.atomic.spinLoopHint;
