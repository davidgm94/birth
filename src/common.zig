const compiler_builtin = @import("builtin");
pub const cpu = compiler_builtin.cpu;
pub const os = compiler_builtin.os.tag;
pub const build_mode = compiler_builtin.mode;
pub const is_test = compiler_builtin.is_test;

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
pub const parseUnsigned = fmt.parseUnsigned;

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
pub const tokenize = mem.tokenize;

pub const random = std.rand;

pub const testing = std.testing;

pub const sort = std.sort.sort;

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
pub const AutoEnumArray = std.enums.EnumArray;
pub const fields = std.meta.fields;
pub const IntType = std.meta.Int;
pub const stringToEnum = std.meta.stringToEnum;
pub const Tag = std.meta.Tag;

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

pub fn enumValues(comptime E: type) []const Type.EnumField {
    return @typeInfo(E).Enum.fields;
}

pub fn enumCount(comptime E: type) usize {
    return enumValues(E).len;
}

pub const PartitionTableType = enum {
    mbr,
    gpt,
};

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

pub const Bootloader = enum(u32) {
    rise,
    limine,

    pub const Protocol = enum(u32) {
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

pub const QEMU = extern struct {
    isa_debug_exit: ISADebugExit,

    pub const ISADebugExit = extern struct {
        io_base: u8 = 0xf4,
        io_size: u8 = @sizeOf(u32),
    };
};
