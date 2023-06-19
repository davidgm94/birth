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

pub const Atomic = std.atomic.Atomic;

pub const Reader = std.io.Reader;
pub const Writer = std.io.Writer;

pub const FixedBufferStream = std.io.FixedBufferStream;
pub const fixedBufferStream = std.io.fixedBufferStream;

pub fn assert(ok: bool) void {
    if (!ok) {
        if (@inComptime()) {
            @compileError("Assert failed!");
        } else {
            @panic("Assert failed!");
        }
    }
}

pub const deflate = std.compress.deflate;

const debug = std.debug;
pub const print = debug.print;
pub const StackIterator = debug.StackIterator;
pub const dwarf = std.dwarf;
pub const ModuleDebugInfo = std.debug.ModuleDebugInfo;

pub const elf = std.elf;

const fmt = std.fmt;
pub const format = std.fmt.format;
pub const FormatOptions = fmt.FormatOptions;
pub const bufPrint = fmt.bufPrint;
pub const allocPrint = fmt.allocPrint;
pub const comptimePrint = fmt.comptimePrint;
pub const parseUnsigned = fmt.parseUnsigned;

const heap = std.heap;
pub const FixedBufferAllocator = heap.FixedBufferAllocator;

pub const json = std.json;

const mem = std.mem;
pub const ZigAllocator = mem.Allocator;
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
pub const alignBackward = mem.alignBackward;
pub const isAligned = mem.isAligned;
pub const isAlignedGeneric = mem.isAlignedGeneric;
pub const reverse = mem.reverse;
pub const tokenize = mem.tokenize;
pub const containsAtLeast = mem.containsAtLeast;
pub const sliceTo = mem.sliceTo;
pub const swap = mem.swap;

pub const random = std.rand;

pub const testing = std.testing;

pub const sort = std.sort;

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
    for (file1, 0..) |byte1, index| {
        const byte2 = file2[index];
        const is_different_byte = byte1 != byte2;
        different_bytes += @intFromBool(is_different_byte);
        if (is_different_byte) {
            log.debug("Byte [0x{x}] is different: 0x{x} != 0x{x}", .{ index, byte1, byte2 });
        }
    }

    if (different_bytes != 0) {
        log.debug("Total different bytes: 0x{x}", .{different_bytes});
        return DiffError.diff;
    }
}

pub fn zeroes(comptime T: type) T {
    var result: T = undefined;
    const slice = asBytes(&result);
    @memset(slice, 0);
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

pub fn FieldType(comptime T: type, comptime name: []const u8) type {
    return @TypeOf(@field(@as(T, undefined), name));
}

// META PROGRAMMING
pub const AutoEnumArray = std.enums.EnumArray;
pub const fields = std.meta.fields;
pub const IntType = std.meta.Int;
pub const enumFromInt = std.meta.enumFromInt;
pub const stringToEnum = std.meta.stringToEnum;
pub const Tag = std.meta.Tag;

const math = std.math;
pub const maxInt = math.maxInt;
pub const min = math.min;
pub const divCeil = math.divCeil;
pub const clamp = math.clamp;
pub const isPowerOfTwo = math.isPowerOfTwo;
pub const mul = math.mul;
pub const cast = math.cast;

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

pub fn enumFields(comptime E: type) []const Type.EnumField {
    return @typeInfo(E).Enum.fields;
}

pub const enumValues = std.enums.values;

pub fn enumCount(comptime E: type) usize {
    return enumFields(E).len;
}

pub const PartitionTableType = enum {
    mbr,
    gpt,
};

pub const supported_architectures = [_]Cpu.Arch{
    .x86_64,
    //.aarch64,
    //.riscv64,
};

pub fn architectureIndex(comptime arch: Cpu.Arch) comptime_int {
    inline for (supported_architectures, 0..) |architecture, index| {
        if (arch == architecture) return index;
    }

    @compileError("Architecture not found");
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

    // array[architectureIndex(.aarch64)] = &.{
    //     .{
    //         .id = .rise,
    //         .protocols = &.{.uefi},
    //     },
    //     .{
    //         .id = .limine,
    //         .protocols = &.{.uefi},
    //     },
    // };

    // array[architectureIndex(.riscv64)] = &.{
    //     .{
    //         .id = .rise,
    //         .protocols = &.{.uefi},
    //     },
    // };

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

pub const TraditionalExecutionMode = enum(u1) {
    privileged = 0,
    user = 1,
};

pub const ExecutionEnvironment = enum {
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
        const parsed_image_configuration = try std.json.parseFromSlice(ImageConfig, allocator, image_config_file, .{});
        return parsed_image_configuration.value;
    }
};

pub const PartitionConfig = struct {
    name: []const u8,
    filesystem: FilesystemType,
    first_lba: u64,
};

pub const QEMU = extern struct {
    pub const isa_debug_exit = ISADebugExit{};

    pub const ISADebugExit = extern struct {
        io_base: u8 = 0xf4,
        io_size: u8 = @sizeOf(u32),
    };

    pub const ExitCode = enum(u32) {
        success = 0x10,
        failure = 0x11,
        _,
    };
};

pub const OptimizeMode = std.builtin.OptimizeMode;

pub const Configuration = struct {
    architecture: Cpu.Arch,
    bootloader: Bootloader,
    boot_protocol: Bootloader.Protocol,
    execution_environment: ExecutionEnvironment,
    optimize_mode: OptimizeMode,
    execution_type: ExecutionType,
    executable_kind: std.Build.CompileStep.Kind,
};

pub const QEMUOptions = packed struct {
    is_test: bool,
    is_debug: bool,
};

pub const ExecutionType = enum {
    emulated,
    accelerated,
};

pub const Suffix = enum {
    bootloader,
    cpu_driver,
    image,
    complete,

    pub fn fromConfiguration(suffix: Suffix, allocator: ZigAllocator, configuration: Configuration, prefix: ?[]const u8) ![]const u8 {
        const cpu_driver_suffix = [_][]const u8{
            @tagName(configuration.optimize_mode),
            "_",
            @tagName(configuration.architecture),
            "_",
            @tagName(configuration.executable_kind),
        };

        const bootloader_suffix = [_][]const u8{
            @tagName(configuration.architecture),
            "_",
            @tagName(configuration.bootloader),
            "_",
            @tagName(configuration.boot_protocol),
        };

        const image_suffix = [_][]const u8{
            @tagName(configuration.optimize_mode),
            "_",
        } ++ bootloader_suffix ++ [_][]const u8{
            "_",
            @tagName(configuration.executable_kind),
        };

        const complete_suffix = image_suffix ++ [_][]const u8{
            "_",
            @tagName(configuration.execution_type),
            "_",
            @tagName(configuration.execution_environment),
        };

        return try std.mem.concat(allocator, u8, &switch (suffix) {
            .cpu_driver => if (prefix) |pf| [1][]const u8{pf} ++ cpu_driver_suffix else cpu_driver_suffix,
            .bootloader => if (prefix) |pf| [1][]const u8{pf} ++ bootloader_suffix else bootloader_suffix,
            .image => if (prefix) |pf| [1][]const u8{pf} ++ image_suffix else image_suffix,
            .complete => if (prefix) |pf| [1][]const u8{pf} ++ complete_suffix else complete_suffix,
        });
    }
};

pub const Module = struct {
    program: UserProgram,
    name: []const u8,
};
pub const UserProgram = struct {
    kind: Kind,
    dependencies: []const Dependency,

    pub const Kind = enum {
        zig_exe,
    };

    pub const Dependency = struct {
        foo: u64 = 0,
    };
};

pub const RiseProgram = enum {
    bootloader,
    cpu,
    user,
    host,
};

pub fn canVirtualizeWithQEMU(architecture: Cpu.Arch, ci: bool) bool {
    if (architecture != cpu.arch) return false;
    if (ci) return false;

    return switch (os) {
        .linux => blk: {
            const uname = std.os.uname();
            const release = &uname.release;
            break :blk !containsAtLeast(u8, release, 1, "WSL") and !containsAtLeast(u8, release, 1, "microsoft");
        },
        else => false,
    };
}

pub const default_cpu_name = "/cpu";
pub const default_init_file = "/init";

pub const ArgumentParser = struct {
    pub const null_specifier = "-";

    pub const DiskImageBuilder = struct {
        argument_index: usize = 0,

        pub const ArgumentType = enum {
            disk_image_path,
            configuration,
            image_configuration_path,
            bootloader,
            cpu,
            user_programs,
        };

        pub const Result = struct {
            bootloader: []const u8,
            disk_image_path: []const u8,
            image_configuration_path: []const u8,
            cpu: []const u8,
            user_programs: []const []const u8,
            configuration: Configuration,
        };

        pub fn next(argument_parser: *ArgumentParser.DiskImageBuilder) ?ArgumentType {
            if (argument_parser.argument_index < enumCount(ArgumentType)) {
                const result: ArgumentType = @enumFromInt(argument_parser.argument_index);
                argument_parser.argument_index += 1;
                return result;
            }

            return null;
        }
    };

    pub const Runner = struct {
        argument_index: usize = 0,

        pub fn next(argument_parser: *ArgumentParser.Runner) ?ArgumentType {
            if (argument_parser.argument_index < enumCount(ArgumentType)) {
                const result: ArgumentType = @enumFromInt(argument_parser.argument_index);
                argument_parser.argument_index += 1;
                return result;
            }

            return null;
        }

        pub const ArgumentType = enum {
            configuration,
            disk_image_path,
            image_configuration_path,
            cpu_driver,
            loader_path,
            qemu_options,
            ci,
            debug_user,
            debug_loader,
            init,
        };

        pub const Result = struct {
            configuration: Configuration,
            disk_image_path: []const u8,
            image_configuration_path: []const u8,
            cpu_driver: []const u8,
            loader_path: []const u8,
            qemu_options: QEMUOptions,
            ci: bool,
            debug_user: bool,
            debug_loader: bool,
            init: []const u8,
        };
    };
};

pub const default_disk_size = 64 * 1024 * 1024;
pub const default_sector_size = 0x200;
