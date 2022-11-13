pub const std = @import("std");
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
pub const div_ceil = std.math.divCeil;
pub const clamp = std.math.clamp;
pub const is_power_of_two = std.math.isPowerOfTwo;
pub const mul = std.math.mul;

// MEMORY ALLOCATION
pub const Allocator = std.mem.Allocator;
pub const AllocatorAllocFunction = fn (context: *anyopaque, len: usize, ptr_align: u29, len_align: u29, return_address: usize) Allocator.Error![]u8;
pub const AllocatorResizeFunction = fn (context: *anyopaque, old_mem: []u8, old_align: u29, new_size: usize, len_align: u29, return_address: usize) ?usize;
pub const AllocatorFreeFunction = fn (context: *anyopaque, old_mem: []u8, old_align: u29, return_address: usize) void;
pub const FixedBufferAllocator = std.heap.FixedBufferAllocator;

// DATA STRUCTURES
pub const ArrayList = std.ArrayListUnmanaged;
pub const ArrayListAligned = std.ArrayListAlignedUnmanaged;
pub const ArrayListManaged = std.ArrayList;
pub const ArrayListAlignedManaged = std.ArrayListAligned;
pub const Bitset = std.StaticBitSet;
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
pub const last_index_of = std.mem.lastIndexOf;
pub const as_bytes = std.mem.asBytes;
pub const internal_read_int_big = std.mem.readIntBig;
pub const read_int_slice_big_endian = std.mem.readIntSliceBig;
pub const concatenate = std.mem.concat;
pub const slice_as_bytes = std.mem.sliceAsBytes;
pub const bytes_as_slice = std.mem.bytesAsSlice;

// TEST
pub const expect = std.testing.expect;
pub const expect_equal = std.testing.expectEqual;

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

pub fn is_same_packed_size(comptime A: type, comptime B: type) bool {
    return @bitSizeOf(A) == @bitSizeOf(B) and @sizeOf(A) == @sizeOf(B);
}

pub fn enum_count(comptime E: type) usize {
    return @typeInfo(E).Enum.fields.len;
}

pub fn field_size(comptime T: type, field_name: []const u8) comptime_int {
    var foo: T = undefined;
    return @sizeOf(@TypeOf(@field(foo, field_name)));
}

pub const CustomAllocator = extern struct {
    callback_allocate: *const AllocateFunction,
    callback_resize: *const ResizeFunction,
    callback_free: *const FreeFunction,

    pub fn allocate_bytes(allocator: *CustomAllocator, size: u64, alignment: u64) Error!Result {
        return try allocator.callback_allocate(allocator, size, alignment);
    }

    pub fn allocate_many(allocator: *CustomAllocator, comptime T: type, count: usize) Error![]T {
        const result = try allocator.callback_allocate(allocator, @sizeOf(T) * count, @alignOf(T));
        return @intToPtr([*]T, result.address)[0..count];
    }

    pub fn realloc(allocator: *CustomAllocator, old_mem: anytype, new_n: usize) t: {
        const Slice = @typeInfo(@TypeOf(old_mem)).Pointer;
        break :t Error![]align(Slice.alignment) Slice.child;
    } {
        const old_alignment = @typeInfo(@TypeOf(old_mem)).Pointer.alignment;
        return allocator.reallocate_advanced(old_mem, old_alignment, new_n);
    }

    pub fn allocate_advanced(allocator: *CustomAllocator, comptime T: type, comptime alignment: ?u29, count: usize) Error![]align(alignment orelse @alignOf(T)) T {
        const a = if (alignment) |a| blk: {
            if (a == @alignOf(T)) return allocator.allocate_advanced(T, null, count);
            break :blk a;
        } else @alignOf(T);

        if (count == 0) {
            return @as([*]align(a) T, undefined)[0..0];
        }

        const byte_count = mul(usize, @sizeOf(T), count) catch return Error.OutOfMemory;
        // TODO The `if (alignment == null)` blocks are workarounds for zig not being able to
        // access certain type information about T without creating a circular dependency in async
        // functions that heap-allocate their own frame with @Frame(func).
        const len_align: u29 = 0;
        _ = len_align;
        const allocation_result = try allocator.callback_allocate(allocator, byte_count, a);
        const byte_slice = allocation_result.to_bytes();
        assert(byte_slice.len == byte_count);
        // TODO: https://github.com/ziglang/zig/issues/4298
        //@memset(byte_slice.ptr, undefined, byte_slice.len);
        if (alignment == null) {
            // This if block is a workaround (see comment above)
            return @intToPtr([*]T, @ptrToInt(byte_slice.ptr))[0..@divExact(byte_slice.len, @sizeOf(T))];
        } else {
            return bytes_as_slice(T, @alignCast(a, byte_slice));
        }
    }

    pub fn reallocate_advanced(allocator: *CustomAllocator, old_mem: anytype, comptime new_alignment: u29, new_n: usize) Error![]align(new_alignment) @typeInfo(@TypeOf(old_mem)).Pointer.child {
        const Slice = @typeInfo(@TypeOf(old_mem)).Pointer;
        const T = Slice.child;
        if (old_mem.len == 0) {
            return allocator.allocate_advanced(T, new_alignment, new_n);
        }
        if (new_n == 0) {
            allocator.free(old_mem);
            return @as([*]align(new_alignment) T, undefined)[0..0];
        }

        const old_byte_slice = slice_as_bytes(old_mem);
        const byte_count = mul(usize, @sizeOf(T), new_n) catch return Error.OutOfMemory;
        // Note: can't set shrunk memory to undefined as memory shouldn't be modified on realloc failure

        const len_align: u29 = 0;
        _ = len_align;

        if (is_aligned(@ptrToInt(old_byte_slice.ptr), new_alignment)) {
            if (byte_count <= old_byte_slice.len) {
                @panic("todo shrink");
                //const shrunk_len = allocator.shrinkBytes(old_byte_slice, Slice.alignment, byte_count, len_align);
                //return common.bytes_as_slice(T, @alignCast(new_alignment, old_byte_slice.ptr[0..shrunk_len]));
            }

            if (allocator.callback_resize(allocator, old_byte_slice, Slice.alignment, byte_count)) |resized_len| {
                // TODO: https://github.com/ziglang/zig/issues/4298
                @memset(old_byte_slice.ptr + byte_count, undefined, resized_len - byte_count);
                return bytes_as_slice(T, @alignCast(new_alignment, old_byte_slice.ptr[0..resized_len]));
            }
        }

        if (byte_count <= old_byte_slice.len and new_alignment <= Slice.alignment) {
            return error.OutOfMemory;
        }

        const new_mem_result = try allocator.callback_allocate(allocator, byte_count, new_alignment);
        const new_mem = new_mem_result.to_bytes();
        @memcpy(new_mem.ptr, old_byte_slice.ptr, min(byte_count, old_byte_slice.len));
        // TODO https://github.com/ziglang/zig/issues/4298
        @memset(old_byte_slice.ptr, undefined, old_byte_slice.len);
        allocator.callback_free(allocator, old_byte_slice, Slice.alignment);

        return bytes_as_slice(T, @alignCast(new_alignment, new_mem));
    }

    pub fn free(allocator: *CustomAllocator, old_mem: anytype) void {
        _ = allocator;
        _ = old_mem;
        @panic("todo free");
    }

    pub fn create(allocator: *CustomAllocator, comptime T: type) Error!*T {
        const result = try allocator.callback_allocate(allocator, @sizeOf(T), @alignOf(T));
        return @intToPtr(*T, result.address);
    }

    pub fn get_allocator(allocator: *const CustomAllocator) Allocator {
        return Allocator{
            .ptr = @intToPtr(*anyopaque, @ptrToInt(allocator)),
            .vtable = &vtable,
        };
    }

    const vtable = Allocator.VTable{
        .alloc = zig_alloc,
        .resize = zig_resize,
        .free = zig_free,
    };

    fn zig_alloc(context: *anyopaque, size: usize, ptr_align: u29, len_align: u29, return_address: usize) Allocator.Error![]u8 {
        _ = len_align;
        _ = return_address;
        const allocator = @ptrCast(*CustomAllocator, @alignCast(@alignOf(CustomAllocator), context));
        const result = allocator.callback_allocate(allocator, size, ptr_align) catch return Allocator.Error.OutOfMemory;
        const byte_slice = @intToPtr([*]u8, result.address)[0..result.size];
        return byte_slice;
    }

    fn zig_resize(context: *anyopaque, old_mem: []u8, old_align: u29, new_size: usize, len_align: u29, return_address: usize) ?usize {
        _ = context;
        _ = old_mem;
        _ = old_align;
        _ = new_size;
        _ = len_align;
        _ = return_address;
        @panic("TODO resize");
    }

    fn zig_free(context: *anyopaque, old_mem: []u8, old_align: u29, return_address: usize) void {
        _ = context;
        _ = old_mem;
        _ = old_align;
        _ = return_address;
        @panic("TODO free");
    }

    //pub const AllocatorAllocFunction = fn (context: *anyopaque, len: usize, ptr_align: u29, len_align: u29, return_address: usize) Allocator.Error![]u8;
    //pub const AllocatorResizeFunction = fn (context: *anyopaque, old_mem: []u8, old_align: u29, new_size: usize, len_align: u29, return_address: usize) ?usize;
    //pub const AllocatorFreeFunction = fn (context: *anyopaque, old_mem: []u8, old_align: u29, return_address: usize) void;
    pub const AllocateFunction = fn (allocator: *CustomAllocator, size: u64, alignment: u64) Error!Result;
    pub const ResizeFunction = fn (allocator: *CustomAllocator, old_memory: []u8, old_alignment: u29, new_size: usize) ?usize;
    pub const FreeFunction = fn (allocator: *CustomAllocator, memory: []u8, alignment: u29) void;

    pub const Result = struct {
        address: u64,
        size: u64,

        pub fn to_bytes(result: Result) []u8 {
            return @intToPtr([*]u8, result.address)[0..result.size];
        }
    };

    pub const Error = error{OutOfMemory};
};

pub const arch = @import("common/arch.zig");
/// This is done so the allocator can respect allocating from different address spaces
pub const config = @import("common/config.zig");
pub const Disk = @import("common/disk.zig");
pub const ELF = @import("common/elf.zig");
pub const Filesystem = @import("common/filesystem.zig");
pub const List = @import("common/list.zig");
pub const Message = @import("common/message.zig");
pub const Module = @import("common/module.zig");
pub const QEMU = @import("common/qemu.zig");
pub const RiseFS = @import("common/risefs.zig");
pub const Syscall = @import("common/syscall.zig");
pub const Graphics = @import("common/graphics.zig");
pub const Window = @import("common/window.zig");
