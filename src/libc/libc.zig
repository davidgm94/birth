const std = @import("std");

export fn floor(x: f64) f64 {
    return @floor(x);
}

export fn ceil(x: f64) f64 {
    return @ceil(x);
}

export fn sqrt(x: f64) f64 {
    return @sqrt(x);
}

export fn pow(base: f64, exponent: f64) f64 {
    return std.math.pow(@TypeOf(base), base, exponent);
}

export fn fmod(x: f64, y: f64) f64 {
    return @mod(x, y);
}

export fn cos(x: f64) f64 {
    return @cos(x);
}

export fn acos(x: f64) f64 {
    return std.math.acos(x);
}

export fn fabs(x: f64) f64 {
    return @fabs(x);
}

export fn strlen(string: [*:0]const u8) usize {
    return std.mem.len(string);
}

export fn assert(condition: bool) void {
    if (!condition) unreachable;
}

export fn memcpy(destination: ?*anyopaque, source: ?*const anyopaque, size: usize) ?*anyopaque {
    if (destination == null) return null;
    if (source == null) return null;
    if (size == 0) return null;

    @memcpy(destination, source, size);
}

export fn memset(destination: ?*anyopaque, character: c_int, size: usize) ?*anyopaque {
    if (destination == null) return null;
    if (size == 0) return null;

    @memset(destination, @intCast(u8, character), size);
}

//export fn void* malloc(size_t size);
//export fn void free(void* ptr);
