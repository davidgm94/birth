const compiler_builtin = @import("builtin");
pub const cpu = compiler_builtin.cpu;
pub const os = compiler_builtin.os.tag;
pub const build_mode = compiler_builtin.mode;

pub const kb = 1024;
pub const mb = kb * 1024;
pub const gb = mb * 1024;
pub const tb = gb * 1024;

pub const SizeUnit = enum(u64) {
    byte = 1,
    kilobyte = 1024,
    megabyte = 1024 * 1024,
    gigabyte = 1024 * 1024 * 1024,
    terabyte = 1024 * 1024 * 1024 * 1024,
};

pub const std = @import("std");
pub const Target = std.Target;
pub const Cpu = Target.Cpu;
pub const CrossTarget = std.zig.CrossTarget;

pub const log = std.log;

pub const Writer = std.io.Writer;

const debug = std.debug;
pub const assert = debug.assert;
pub const print = debug.print;
pub const StackIterator = debug.StackIterator;

const fmt = std.fmt;
pub const format = std.fmt.format;
pub const FormatOptions = fmt.FormatOptions;
pub const bufPrint = fmt.bufPrint;
pub const allocPrint = fmt.allocPrint;
pub const comptimePrint = fmt.comptimePrint;

pub const json = std.json;

const mem = std.mem;
pub const ZigAllocator = mem.Allocator;
pub const copy = mem.copy;
pub const equal = mem.eql;
pub const length = mem.len;
pub const startsWith = mem.startsWith;
pub const endsWith = mem.endsWith;
pub const indexOf = mem.indexOf;
// Ideal for small inputs
pub const indexOfPosLinear = mem.indexOfPosLinear;
pub const lastIndexOf = mem.lastIndexOf;
pub const asBytes = mem.asBytes;
pub const readIntBig = mem.readIntBig;
pub const readIntSliceBig = mem.readIntSliceBig;
pub const concat = mem.concat;
pub const sliceAsBytes = mem.sliceAsBytes;
pub const bytesAsSlice = mem.bytesAsSlice;
pub const alignForward = mem.alignForward;
pub const alignForwardGeneric = mem.alignForwardGeneric;
pub const alignBackward = mem.alignBackward;
pub const alignBackwardGeneric = mem.alignBackwardGeneric;
pub const isAligned = mem.isAligned;
pub const isAlignedGeneric = mem.isAlignedGeneric;
pub const reverse = mem.reverse;

pub const random = std.rand;

pub const testing = std.testing;

pub fn fieldSize(comptime T: type, field_name: []const u8) comptime_int {
    var foo: T = undefined;
    return @sizeOf(@TypeOf(@field(foo, field_name)));
}

const DiffError = error{
    diff,
};

pub fn diff(file1: []const u8, file2: []const u8) !void {
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

    if (different_bytes != 0) {
        log.debug("Total different bytes: 0x{x}", .{different_bytes});
        return DiffError.diff;
    }
}

pub fn zero(slice: []u8) void {
    for (slice) |*byte| {
        byte.* = 0;
    }
}

pub fn zeroes(comptime T: type) T {
    var result: T = undefined;
    const slice = asBytes(&result);
    zero(slice);
    return result;
}

const ascii = std.ascii;
pub const upperString = ascii.upperString;
pub const isUpper = ascii.isUpper;
pub const isAlphabetic = ascii.isAlphabetic;

const std_builtin = std.builtin;
pub const AtomicRmwOp = std_builtin.AtomicRmwOp;
pub const AtomicOrder = std_builtin.AtomicOrder;
pub const Type = std_builtin.Type;
pub const StackTrace = std_builtin.StackTrace;
pub const SourceLocation = std_builtin.SourceLocation;

// META PROGRAMMING
pub const fields = std.meta.fields;
pub const IntType = std.meta.Int;
pub const stringToEnum = std.meta.stringToEnum;

const math = std.math;
pub const maxInt = math.maxInt;
pub const max = math.max;
pub const min = math.min;
pub const divCeil = math.divCeil;
pub const clamp = math.clamp;
pub const isPowerOfTwo = math.isPowerOfTwo;
pub const mul = math.mul;

pub const unicode = std.unicode;

pub const uefi = std.os.uefi;

pub const DiskType = enum(u32) {
    virtio = 0,
    nvme = 1,
    ahci = 2,
    ide = 3,
    memory = 4,
    bios = 5,

    pub const count = enumCount(@This());
};

pub const FilesystemType = enum(u32) {
    rise = 0,
    ext2 = 1,
    fat32 = 2,

    pub const count = enumCount(@This());
};

pub fn enumCount(comptime E: type) usize {
    return @typeInfo(E).Enum.fields.len;
}

// pub const CustomAllocator = extern struct {
//     callback_allocate: *const AllocateFunction,
//     callback_resize: *const ResizeFunction,
//     callback_free: *const FreeFunction,
//
//     pub fn allocate_bytes(allocator: *CustomAllocator, size: u64, alignment: u64) Error!Result {
//         return try allocator.callback_allocate(allocator, size, alignment);
//     }
//
//     pub fn allocate_many(allocator: *CustomAllocator, comptime T: type, count: usize) Error![]T {
//         const result = try allocator.callback_allocate(allocator, @sizeOf(T) * count, @alignOf(T));
//         return @intToPtr([*]T, result.address)[0..count];
//     }
//
//     pub fn realloc(allocator: *CustomAllocator, old_mem: anytype, new_n: usize) t: {
//         const Slice = @typeInfo(@TypeOf(old_mem)).Pointer;
//         break :t Error![]align(Slice.alignment) Slice.child;
//     } {
//         const old_alignment = @typeInfo(@TypeOf(old_mem)).Pointer.alignment;
//         return allocator.reallocate_advanced(old_mem, old_alignment, new_n);
//     }
//
//     pub fn allocate_advanced(allocator: *CustomAllocator, comptime T: type, comptime alignment: ?u29, count: usize) Error![]align(alignment orelse @alignOf(T)) T {
//         const a = if (alignment) |a| blk: {
//             if (a == @alignOf(T)) return allocator.allocate_advanced(T, null, count);
//             break :blk a;
//         } else @alignOf(T);
//
//         if (count == 0) {
//             return @as([*]align(a) T, undefined)[0..0];
//         }
//
//         const byte_count = mul(usize, @sizeOf(T), count) catch return Error.OutOfMemory;
//         // TODO The `if (alignment == null)` blocks are workarounds for zig not being able to
//         // access certain type information about T without creating a circular dependency in async
//         // functions that heap-allocate their own frame with @Frame(func).
//         const len_align: u29 = 0;
//         _ = len_align;
//         const allocation_result = try allocator.callback_allocate(allocator, byte_count, a);
//         const byte_slice = allocation_result.to_bytes();
//         assert(byte_slice.len == byte_count);
//         // TODO: https://github.com/ziglang/zig/issues/4298
//         //@memset(byte_slice.ptr, undefined, byte_slice.len);
//         if (alignment == null) {
//             // This if block is a workaround (see comment above)
//             return @intToPtr([*]T, @ptrToInt(byte_slice.ptr))[0..@divExact(byte_slice.len, @sizeOf(T))];
//         } else {
//             return bytesAsSlice(T, @alignCast(a, byte_slice));
//         }
//     }
//
//     pub fn reallocate_advanced(allocator: *CustomAllocator, old_mem: anytype, comptime new_alignment: u29, new_n: usize) Error![]align(new_alignment) @typeInfo(@TypeOf(old_mem)).Pointer.child {
//         const Slice = @typeInfo(@TypeOf(old_mem)).Pointer;
//         const T = Slice.child;
//         if (old_mem.len == 0) {
//             return allocator.allocate_advanced(T, new_alignment, new_n);
//         }
//         if (new_n == 0) {
//             allocator.free(old_mem);
//             return @as([*]align(new_alignment) T, undefined)[0..0];
//         }
//
//         const old_byte_slice = sliceAsBytes(old_mem);
//         const byte_count = mul(usize, @sizeOf(T), new_n) catch return Error.OutOfMemory;
//         // Note: can't set shrunk memory to undefined as memory shouldn't be modified on realloc failure
//
//         const len_align: u29 = 0;
//         _ = len_align;
//
//         if (isAligned(@ptrToInt(old_byte_slice.ptr), new_alignment)) {
//             if (byte_count <= old_byte_slice.len) {
//                 @panic("todo shrink");
//                 //const shrunk_len = allocator.shrinkBytes(old_byte_slice, Slice.alignment, byte_count, len_align);
//                 //return common.bytes_as_slice(T, @alignCast(new_alignment, old_byte_slice.ptr[0..shrunk_len]));
//             }
//
//             if (allocator.callback_resize(allocator, old_byte_slice, Slice.alignment, byte_count)) |resized_len| {
//                 // TODO: https://github.com/ziglang/zig/issues/4298
//                 @memset(old_byte_slice.ptr + byte_count, undefined, resized_len - byte_count);
//                 return bytesAsSlice(T, @alignCast(new_alignment, old_byte_slice.ptr[0..resized_len]));
//             }
//         }
//
//         if (byte_count <= old_byte_slice.len and new_alignment <= Slice.alignment) {
//             return error.OutOfMemory;
//         }
//
//         const new_mem_result = try allocator.callback_allocate(allocator, byte_count, new_alignment);
//         const new_mem = new_mem_result.to_bytes();
//         @memcpy(new_mem.ptr, old_byte_slice.ptr, min(byte_count, old_byte_slice.len));
//         // TODO https://github.com/ziglang/zig/issues/4298
//         @memset(old_byte_slice.ptr, undefined, old_byte_slice.len);
//         allocator.callback_free(allocator, old_byte_slice, Slice.alignment);
//
//         return bytesAsSlice(T, @alignCast(new_alignment, new_mem));
//     }
//
//     pub fn free(allocator: *CustomAllocator, old_mem: anytype) void {
//         _ = allocator;
//         _ = old_mem;
//         @panic("todo free");
//     }
//
//     pub fn create(allocator: *CustomAllocator, comptime T: type) Error!*T {
//         const result = try allocator.callback_allocate(allocator, @sizeOf(T), @alignOf(T));
//         return @intToPtr(*T, result.address);
//     }
//
//     pub fn get_allocator(allocator: *const CustomAllocator) Allocator {
//         return Allocator{
//             .ptr = @intToPtr(*anyopaque, @ptrToInt(allocator)),
//             .vtable = &vtable,
//         };
//     }
//
//     const vtable = Allocator.VTable{
//         .alloc = zig_alloc,
//         .resize = zig_resize,
//         .free = zig_free,
//     };
//
//     fn zig_alloc(context: *anyopaque, size: usize, ptr_align: u29, len_align: u29, return_address: usize) Allocator.Error![]u8 {
//         _ = len_align;
//         _ = return_address;
//         const allocator = @ptrCast(*CustomAllocator, @alignCast(@alignOf(CustomAllocator), context));
//         const result = allocator.callback_allocate(allocator, size, ptr_align) catch return Allocator.Error.OutOfMemory;
//         const byte_slice = @intToPtr([*]u8, result.address)[0..result.size];
//         return byte_slice;
//     }
//
//     fn zig_resize(context: *anyopaque, old_mem: []u8, old_align: u29, new_size: usize, len_align: u29, return_address: usize) ?usize {
//         _ = context;
//         _ = old_mem;
//         _ = old_align;
//         _ = new_size;
//         _ = len_align;
//         _ = return_address;
//         @panic("TODO resize");
//     }
//
//     fn zig_free(context: *anyopaque, old_mem: []u8, old_align: u29, return_address: usize) void {
//         _ = context;
//         _ = old_mem;
//         _ = old_align;
//         _ = return_address;
//         @panic("TODO free");
//     }
//
//     pub const AllocateFunction = fn (allocator: *CustomAllocator, size: u64, alignment: u64) Error!Result;
//     pub const ResizeFunction = fn (allocator: *CustomAllocator, old_memory: []u8, old_alignment: u29, new_size: usize) ?usize;
//     pub const FreeFunction = fn (allocator: *CustomAllocator, memory: []u8, alignment: u29) void;
//
//     pub const Result = struct {
//         address: u64,
//         size: u64,
//
//         pub fn to_bytes(result: Result) []u8 {
//             return @intToPtr([*]u8, result.address)[0..result.size];
//         }
//     };
//
//     pub const Error = error{OutOfMemory};
// };

pub const PartitionTableType = enum {
    mbr,
    gpt,
};

// pub const Bootloader = struct {
//     supported_architectures: []const Architecture,
//
//     pub const Architecture = struct {
//         id: Cpu.Arch,
//         supported_protocols: []const Protocol,
//     };
//
//     pub const Protocol = enum(u8) {
//         bios,
//         uefi,
//     };
//
//     pub const ID = enum(u1) {
//         rise = 0,
//         limine = 1,
//     };
//
//     pub const count = enumCount(ID);
// };

// pub const bootloaders = blk: {
//     var loaders: [Bootloader.count]Bootloader = undefined;
//
//     loaders[@enumToInt(Bootloader.ID.rise)] = .{
//         .supported_architectures = &.{
//             .{
//                 .id = .x86_64,
//                 .supported_protocols = &.{ .bios, .uefi },
//             },
//         },
//     };
//     loaders[@enumToInt(Bootloader.ID.limine)] = .{
//         .supported_architectures = &.{
//             .{
//                 .id = .x86_64,
//                 .supported_protocols = &.{ .bios, .uefi },
//             },
//         },
//     };
//
//     break :blk loaders;
// };

pub const supported_architectures = [_]Cpu.Arch{.x86_64};

pub fn architectureIndex(comptime arch: Cpu.Arch) comptime_int {
    inline for (supported_architectures) |architecture, index| {
        if (arch == architecture) return index;
    }

    @panic("WTF");
}
pub const architecture_bootloader_map = blk: {
    var array: [supported_architectures.len][]const ArchitectureBootloader = undefined;

    array[architectureIndex(.x86_64)] = &.{
        .{
            .id = .rise,
            .protocols = &.{ .bios, .uefi },
        },
        .{
            .id = .limine,
            .protocols = &.{ .bios, .uefi },
        },
    };

    break :blk array;
};

pub const Bootloader = enum(u8) {
    rise,
    limine,

    pub const Protocol = enum(u8) {
        bios,
        uefi,
    };
};

pub const ArchitectureBootloader = struct {
    id: Bootloader,
    protocols: []const Bootloader.Protocol,
};

pub const TraditionalExecutionMode = enum {
    privileged,
    user,
};

pub const Emulator = enum {
    qemu,
};

pub const ImageConfig = struct {
    image_name: []const u8,
    sector_count: u64,
    sector_size: u16,
    partition_table: PartitionTableType,
    partition: PartitionConfig,

    pub const default_path = "config/image_config.json";

    pub fn get(allocator: ZigAllocator, path: []const u8) !ImageConfig {
        const image_config_file = try std.fs.cwd().readFileAlloc(allocator, path, maxInt(usize));
        var json_stream = std.json.TokenStream.init(image_config_file);
        return try std.json.parse(ImageConfig, &json_stream, .{ .allocator = allocator });
    }
};

pub const PartitionConfig = struct {
    name: []const u8,
    filesystem: FilesystemType,
    first_lba: u64,
};
