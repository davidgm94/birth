const CustomAllocator = @This();

const common = @import("../common.zig");
const Allocator = common.Allocator;
const assert = common.assert;

callback_allocate: *const AllocateFunction,
callback_resize: *const ResizeFunction,
callback_free: *const FreeFunction,
context: ?*anyopaque,

pub fn allocate_bytes(allocator: CustomAllocator, size: u64, alignment: u64) Error!Result {
    return try allocator.callback_allocate(allocator, size, alignment);
}

pub fn allocate_many(allocator: CustomAllocator, comptime T: type, count: usize) Error![]T {
    const result = try allocator.callback_allocate(allocator, @sizeOf(T) * count, @alignOf(T));
    return @intToPtr([*]T, result.address)[0..count];
}

pub fn realloc(allocator: CustomAllocator, old_mem: anytype, new_n: usize) t: {
    const Slice = @typeInfo(@TypeOf(old_mem)).Pointer;
    break :t Error![]align(Slice.alignment) Slice.child;
} {
    const old_alignment = @typeInfo(@TypeOf(old_mem)).Pointer.alignment;
    return allocator.reallocate_advanced(old_mem, old_alignment, new_n);
}

pub fn allocate_advanced(allocator: CustomAllocator, comptime T: type, comptime alignment: ?u29, count: usize) Error![]align(alignment orelse @alignOf(T)) T {
    const a = if (alignment) |a| blk: {
        if (a == @alignOf(T)) return allocator.allocate_advanced(T, null, count);
        break :blk a;
    } else @alignOf(T);

    if (count == 0) {
        return @as([*]align(a) T, undefined)[0..0];
    }

    const byte_count = common.mul(usize, @sizeOf(T), count) catch return Error.OutOfMemory;
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
        return common.bytes_as_slice(T, @alignCast(a, byte_slice));
    }
}

pub fn reallocate_advanced(allocator: CustomAllocator, old_mem: anytype, comptime new_alignment: u29, new_n: usize) Error![]align(new_alignment) @typeInfo(@TypeOf(old_mem)).Pointer.child {
    const Slice = @typeInfo(@TypeOf(old_mem)).Pointer;
    const T = Slice.child;
    if (old_mem.len == 0) {
        return allocator.allocate_advanced(T, new_alignment, new_n);
    }
    if (new_n == 0) {
        allocator.free(old_mem);
        return @as([*]align(new_alignment) T, undefined)[0..0];
    }

    const old_byte_slice = common.slice_as_bytes(old_mem);
    const byte_count = common.mul(usize, @sizeOf(T), new_n) catch return Error.OutOfMemory;
    // Note: can't set shrunk memory to undefined as memory shouldn't be modified on realloc failure

    const len_align: u29 = 0;
    _ = len_align;

    if (common.is_aligned(@ptrToInt(old_byte_slice.ptr), new_alignment)) {
        if (byte_count <= old_byte_slice.len) {
            @panic("todo shrink");
            //const shrunk_len = allocator.shrinkBytes(old_byte_slice, Slice.alignment, byte_count, len_align);
            //return common.bytes_as_slice(T, @alignCast(new_alignment, old_byte_slice.ptr[0..shrunk_len]));
        }

        if (allocator.callback_resize(allocator, old_byte_slice, Slice.alignment, byte_count)) |resized_len| {
            // TODO: https://github.com/ziglang/zig/issues/4298
            @memset(old_byte_slice.ptr + byte_count, undefined, resized_len - byte_count);
            return common.bytes_as_slice(T, @alignCast(new_alignment, old_byte_slice.ptr[0..resized_len]));
        }
    }

    if (byte_count <= old_byte_slice.len and new_alignment <= Slice.alignment) {
        return error.OutOfMemory;
    }

    const new_mem_result = try allocator.callback_allocate(allocator, byte_count, new_alignment);
    const new_mem = new_mem_result.to_bytes();
    @memcpy(new_mem.ptr, old_byte_slice.ptr, common.min(byte_count, old_byte_slice.len));
    // TODO https://github.com/ziglang/zig/issues/4298
    @memset(old_byte_slice.ptr, undefined, old_byte_slice.len);
    allocator.callback_free(allocator, old_byte_slice, Slice.alignment);

    return common.bytes_as_slice(T, @alignCast(new_alignment, new_mem));
}

pub fn free(allocator: CustomAllocator, old_mem: anytype) void {
    _ = allocator;
    _ = old_mem;
    @panic("todo free");
}

pub fn create(allocator: CustomAllocator, comptime T: type) Error!*T {
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
    const result = allocator.callback_allocate(allocator.*, size, ptr_align) catch return Allocator.Error.OutOfMemory;
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
pub const AllocateFunction = fn (allocator: CustomAllocator, size: u64, alignment: u64) Error!Result;
pub const ResizeFunction = fn (allocator: CustomAllocator, old_memory: []u8, old_alignment: u29, new_size: usize) ?usize;
pub const FreeFunction = fn (allocator: CustomAllocator, memory: []u8, alignment: u29) void;

pub const Result = struct {
    address: u64,
    size: u64,

    pub fn to_bytes(result: Result) []u8 {
        return @intToPtr([*]u8, result.address)[0..result.size];
    }
};

pub const Error = error{OutOfMemory};
