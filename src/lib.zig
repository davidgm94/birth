const std = @import("std");
pub const build = std.build;
const builtin = @import("builtin");

pub const arch = @import("lib/arch.zig");
/// This is done so the allocator can respect allocating from different address spaces
pub const config = @import("lib/config.zig");
pub const CRC32 = @import("lib/crc32.zig");
const disk_file = @import("lib/disk.zig");
pub const Disk = disk_file.Disk;
pub const ELF = @import("lib/elf.zig");
pub const Filesystem = @import("lib/filesystem.zig");
pub const List = @import("lib/list.zig");
pub const Message = @import("lib/message.zig");
pub const Module = @import("lib/module.zig");
pub const PartitionTable = @import("lib/partition_table.zig");
pub const QEMU = @import("lib/qemu.zig");
pub const Syscall = @import("lib/syscall.zig");
pub const Graphics = @import("lib/graphics.zig");
pub const Window = @import("lib/window.zig");

pub const Target = std.Target;
pub const Cpu = Target.Cpu;
pub const CrossTarget = std.zig.CrossTarget;

pub const cpu = builtin.cpu;
pub const os = builtin.os.tag;
pub const build_mode = builtin.mode;

pub const assert = std.debug.assert;

pub const uefi = std.os.uefi;

// ASCII
pub const upperString = std.ascii.upperString;

// META PROGRAMMING
pub const refAllDecls = testing.refAllDecls;
pub const Type = std.builtin.Type;
pub const fields = std.meta.fields;
pub const enumValues = std.enums.values;
pub const IntType = std.meta.Int;

// MATH
pub const maxInt = std.math.maxInt;
pub const max = std.math.max;
pub const min = std.math.min;
pub const divCeil = std.math.divCeil;
pub const clamp = std.math.clamp;
pub const isPowerOfTwo = std.math.isPowerOfTwo;
pub const mul = std.math.mul;

// UNICODE
pub const unicode = std.unicode;

// MEMORY ALLOCATION
pub const Allocator = std.mem.Allocator;
pub const AllocatorAllocFunction = fn (context: *anyopaque, len: usize, ptr_align: u29, len_align: u29, return_address: usize) Allocator.Error![]u8;
pub const AllocatorResizeFunction = fn (context: *anyopaque, old_mem: []u8, old_align: u29, new_size: usize, len_align: u29, return_address: usize) ?usize;
pub const AllocatorFreeFunction = fn (context: *anyopaque, old_mem: []u8, old_align: u29, return_address: usize) void;
pub const ArenaAllocator = std.heap.ArenaAllocator;
pub const FixedBufferAllocator = std.heap.FixedBufferAllocator;
pub const GPA = std.heap.GeneralPurposeAllocator;
pub const page_allocator = std.heap.page_allocator;

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

// FORMAT
pub const format = std.fmt.format;
pub const FormatOptions = std.fmt.FormatOptions;
pub const bufPrint = std.fmt.bufPrint;
pub const allocPrint = std.fmt.allocPrint;
pub const comptimePrint = std.fmt.comptimePrint;

// IO
pub const Writer = std.io.Writer;
pub const getStdOut = std.io.getStdOut;
pub const getStdIn = std.io.getStdIn;

// MEMORY MANIPULATION
pub const copy = std.mem.copy;
pub const equal = std.mem.eql;
pub const length = std.mem.len;
pub const startsWith = std.mem.startsWith;
pub const endsWith = std.mem.endsWith;
pub const lastIndexOf = std.mem.lastIndexOf;
pub const asBytes = std.mem.asBytes;
pub const readIntBig = std.mem.readIntBig;
pub const readIntSliceBig = std.mem.readIntSliceBig;
pub const concat = std.mem.concat;
pub const sliceAsBytes = std.mem.sliceAsBytes;
pub const bytesAsSlice = std.mem.bytesAsSlice;
pub const alignForward = std.mem.alignForward;
pub const alignForwardGeneric = std.mem.alignForwardGeneric;
pub const alignBackward = std.mem.alignBackward;
pub const alignBackwardGeneric = std.mem.alignBackwardGeneric;
pub const isAligned = std.mem.isAligned;
pub const reverse = std.mem.reverse;
pub const tokenize = std.mem.tokenize;

pub fn zero(slice: []u8) void {
    @memset(slice.ptr, 0, slice.len);
}

pub fn zeroes(comptime T: type) T {
    var result: T = undefined;
    const slice = asBytes(&result);
    zero(slice);
    return result;
}

pub const testing = std.testing;

// FILESYSTEM
pub const cwd = std.fs.cwd;
pub const sync = std.os.sync;

pub const ChildProcess = std.ChildProcess;

// JSON
pub const json = std.json;

// SIZES
pub const kb = 1024;
pub const mb = kb * 1024;
pub const gb = mb * 1024;
pub const tb = gb * 1024;

// POSIX
pub const posix = std.os;

// RANDOM
pub const random = std.rand;

// TIME
pub const Instant = std.time.Instant;

pub fn enumCount(comptime E: type) usize {
    return @typeInfo(E).Enum.fields.len;
}

pub fn fieldSize(comptime T: type, field_name: []const u8) comptime_int {
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
            return bytesAsSlice(T, @alignCast(a, byte_slice));
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

        const old_byte_slice = sliceAsBytes(old_mem);
        const byte_count = mul(usize, @sizeOf(T), new_n) catch return Error.OutOfMemory;
        // Note: can't set shrunk memory to undefined as memory shouldn't be modified on realloc failure

        const len_align: u29 = 0;
        _ = len_align;

        if (isAligned(@ptrToInt(old_byte_slice.ptr), new_alignment)) {
            if (byte_count <= old_byte_slice.len) {
                @panic("todo shrink");
                //const shrunk_len = allocator.shrinkBytes(old_byte_slice, Slice.alignment, byte_count, len_align);
                //return common.bytes_as_slice(T, @alignCast(new_alignment, old_byte_slice.ptr[0..shrunk_len]));
            }

            if (allocator.callback_resize(allocator, old_byte_slice, Slice.alignment, byte_count)) |resized_len| {
                // TODO: https://github.com/ziglang/zig/issues/4298
                @memset(old_byte_slice.ptr + byte_count, undefined, resized_len - byte_count);
                return bytesAsSlice(T, @alignCast(new_alignment, old_byte_slice.ptr[0..resized_len]));
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

        return bytesAsSlice(T, @alignCast(new_alignment, new_mem));
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

pub fn diff(file1: []const u8, file2: []const u8) void {
    assert(file1.len == file2.len);
    var different_bytes: u64 = 0;
    for (file1) |byte1, index| {
        const byte2 = file2[index];
        const is_different_byte = byte1 != byte2;
        different_bytes += @boolToInt(is_different_byte);
        if (is_different_byte) {
            log.debug("Byte [0x{x}] is different: 0x{x} != 0x{x}", .{ index, byte1, byte2 });
        }
    }

    log.debug("Total different bytes: 0x{x}", .{different_bytes});
}

pub fn allocate_zero_memory(bytes: u64) ![]align(0x1000) u8 {
    switch (os) {
        .windows => {
            const windows = std.os.windows;
            return @ptrCast([*]align(0x1000) u8, @alignCast(0x1000, try windows.VirtualAlloc(null, bytes, windows.MEM_RESERVE | windows.MEM_COMMIT, windows.PAGE_READWRITE)))[0..bytes];
        },
        // Assume all systems are POSIX
        else => {
            const mmap = std.os.mmap;
            const PROT = std.os.PROT;
            const MAP = std.os.MAP;
            return try mmap(null, bytes, PROT.READ | PROT.WRITE, MAP.PRIVATE | MAP.ANONYMOUS, -1, 0);
        },
        .freestanding => @compileError("Not implemented yet"),
    }
}

pub fn spawnProcess(arguments: []const []const u8, allocator: Allocator) !void {
    var process = ChildProcess.init(arguments, allocator);
    _ = try process.spawnAndWait();
}

test {
    _ = Filesystem;
    _ = PartitionTable;
}
