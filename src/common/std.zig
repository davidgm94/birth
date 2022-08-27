const std = @import("std");
const builtin = @import("builtin");

pub const Cpu = std.Target.Cpu;
pub const cpu = builtin.cpu;
pub const os = builtin.os.tag;

// BUILD
pub const build_mode = builtin.mode;

// META PROGRAMMING
pub const reference_all_declarations = std.testing.refAllDecls;
pub const Type = std.builtin.Type;
pub const fields = std.meta.fields;
pub const enum_values = std.enums.values;
pub const IntType = std.meta.Int;

// MATH
pub const max_int = std.math.maxInt;
pub const max = std.math.max;
pub const min = std.math.min;

// MEMORY ALLOCATION
pub const Allocator = std.mem.Allocator;

// DATA STRUCTURES
pub const ArrayList = std.ArrayListUnmanaged;
pub const ArrayListAligned = std.ArrayListAlignedUnmanaged;
pub const ArrayListManaged = std.ArrayList;
pub const ArrayListAlignedManaged = std.ArrayListAligned;
pub const MultiArrayList = std.MultiArrayList;
pub const SegmentedList = std.SegmentedList;
pub const SinglyLinkedList = std.SinglyLinkedList;
pub const TailQueue = std.TailQueue;

// DEBUG
pub const StackTrace = std.builtin.StackTrace;
pub const SourceLocation = std.builtin.SourceLocation;
pub const StackIterator = std.debug.StackIterator;

// ATOMIC
pub const AtomicRmwOp = std.builtin.AtomicRmwOp;
pub const AtomicOrder = std.builtin.AtomicOrder;
//pub const spinloop_hint = std.atomic.spinLoopHint;

// LOG
pub const log = std.log;

// STDIO
pub const Writer = std.io.Writer;
pub const bufPrint = std.fmt.bufPrint;
pub const allocPrint = std.fmt.allocPrint;

// MEMORY MANIPULATION
pub const equal = std.mem.eql;
pub const length = std.mem.len;
pub const starts_with = std.mem.startsWith;
pub const ends_with = std.mem.endsWith;
pub const as_bytes = std.mem.asBytes;
pub const internal_read_int_big = std.mem.readIntBig;
pub const read_int_slice_big_endian = std.mem.readIntSliceBig;

// INTERNAL
pub const internal_format = std.fmt.format;
pub const InternalFormatOptions = std.fmt.FormatOptions;

// SIZES
pub const kb = 1024;
pub const mb = kb * 1024;
pub const gb = mb * 1024;
pub const tb = gb * 1024;

pub inline fn string_eq(a: []const u8, b: []const u8) bool {
    return equal(u8, a, b);
}

pub inline fn string_starts_with(str: []const u8, slice: []const u8) bool {
    return starts_with(u8, str, slice);
}

pub inline fn string_ends_with(str: []const u8, slice: []const u8) bool {
    return ends_with(u8, str, slice);
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
    return internal_read_int_big(T, slice[0..@sizeOf(T)]);
}
pub fn copy(comptime T: type, dst: []T, src: []const T) void {
    assert(src.len <= dst.len);
    const dst_ptr = @ptrCast([*]u8, dst.ptr);
    const src_ptr = @ptrCast([*]const u8, src.ptr);
    const bytes_to_copy = @sizeOf(T) * src.len;
    @memcpy(dst_ptr, src_ptr, bytes_to_copy);
}

pub inline fn set_byte(slice: []u8, value: u8) void {
    @memset(slice.ptr, value, slice.len);
}

pub inline fn zero_typed_address(address: u64, comptime T: type) *T {
    const result = @intToPtr(*T, address);
    result.* = zeroes(T);
    return result;
}

pub inline fn zero_range(address: u64, size: u64) void {
    zero(@intToPtr([*]u8, address)[0..size]);
}

pub fn zero(bytes: []u8) void {
    set_byte(bytes, 0);
}

pub inline fn zero_slice(comptime T: type, slice: []T) void {
    for (slice) |*elem| {
        elem.* = zeroes(T);
    }
}

pub inline fn zeroes(comptime T: type) T {
    var result: T = undefined;
    zero(as_bytes(&result));
    return result;
}

pub fn assert(condition: bool) void {
    if (!condition) unreachable;
}

pub const MustBeExact = enum {
    must_be_exact,
    can_be_not_exact,
};

pub fn bytes_to_pages_extended(bytes: u64, page_size: u64, comptime must_be_exact: MustBeExact) u64 {
    return remainder_division_maybe_exact(bytes, page_size, must_be_exact);
}

pub fn bytes_to_sector(bytes: u64, sector_size: u64, comptime must_be_exact: MustBeExact) u64 {
    return remainder_division_maybe_exact(bytes, sector_size, must_be_exact);
}

pub fn bytes_to_pages(bytes: u64, page_size: u64, comptime must_be_exact: MustBeExact) u64 {
    return remainder_division_maybe_exact(bytes, page_size, must_be_exact);
}

pub fn remainder_division_maybe_exact(dividend: u64, divisor: u64, comptime must_be_exact: MustBeExact) u64 {
    if (divisor == 0) unreachable;
    const quotient = dividend / divisor;
    const remainder = dividend % divisor;
    const remainder_not_zero = remainder != 0;
    if (must_be_exact == .must_be_exact and remainder_not_zero) @panic("remainder not exact when asked to be exact}");

    return quotient + @boolToInt(remainder_not_zero);
}

pub fn cstr_len(cstr: [*:0]const u8) u64 {
    var len: u64 = 0;
    while (cstr[len] != 0) : (len += 1) {}
    return len;
}

/// @Hack This currently works to determine if the code is being executed at compile time or at run time.
pub fn is_comptime() bool {
    var a: bool = false;
    return @TypeOf(@boolToInt(a)) == comptime_int;
}

pub fn test_comptime_hack() void {
    comptime {
        assert(is_comptime());
    }
    assert(!is_comptime());
}

pub fn is_same_packed_size(comptime A: type, comptime B: type) bool {
    return @bitSizeOf(A) == @bitSizeOf(B) and @sizeOf(A) == @sizeOf(B);
}

pub fn enum_count(comptime E: type) usize {
    return @typeInfo(E).Enum.fields.len;
}
