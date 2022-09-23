//! Only some symbols are exported. The rest are provided by the Zig build

const std = @import("std");

export fn strlen(string: [*:0]const u8) usize {
    return std.mem.len(string);
}

export fn assert(condition: bool) void {
    if (!condition) unreachable;
}

export fn pow(base: f64, exponent: f64) f64 {
    return std.math.pow(@TypeOf(base), base, exponent);
}

export fn acos(x: f64) f64 {
    return std.math.acos(x);
}
