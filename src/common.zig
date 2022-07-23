const root = @import("root");
const std = @import("std");
const builtin = @import("builtin");

pub const ExecutableIdentity = enum {
    kernel,
    kernel_module,
    user,
    build,
};

pub const arch = @import("common/arch.zig");
pub const VirtualAddress = @import("common/virtual_address.zig");
pub const PhysicalAddress = @import("common/physical_address.zig");
pub const VirtualMemoryRegion = @import("common/virtual_memory_region.zig");
pub const PhysicalMemoryRegion = @import("common/physical_memory_region.zig");
pub const PhysicalAddressSpace = @import("common/physical_address_space.zig");
pub const VirtualAddressSpace = @import("common/virtual_address_space.zig");
pub const Thread = @import("common/thread.zig");
pub const Scheduler = @import("common/scheduler.zig");
pub const Syscall = @import("common/syscall.zig");
pub const User = @import("common/user.zig");
pub const List = @import("common/list.zig");
pub const StableBuffer = @import("common/stable_buffer.zig");

pub const Emulator = enum {
    qemu,
    virtualbox,
    vmware,
    bochs,
};

pub const ExitStatus = enum(u32) {
    success = 0,
    failure = 1,
};

pub const DiskDriverType = enum(u32) {
    virtio = 0,
    nvme = 1,
    memory = 2,
};

pub const FilesystemDriverType = enum(u32) {
    RNU = 0,
    ext2 = 1,
};

pub const BootstrapContext = struct {
    cpu: arch.CPU,
    thread: Thread,
    context: arch.Context,
};

pub const emulator_program = Emulator.qemu;
pub const emulator = switch (emulator_program) {
    .qemu => QEMU,
    else => unreachable,
};

pub const QEMU = @import("common/qemu.zig");

pub const ELF = @import("common/elf.zig");
pub const RNUFS = @import("common/rnufs.zig");
pub const PSF1 = @import("common/psf1.zig");
pub const Heap = @import("common/heap.zig");

// ARCH
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

// ATOMIC
pub const AtomicRmwOp = std.builtin.AtomicRmwOp;
pub const AtomicOrder = std.builtin.AtomicOrder;
//pub const spinloop_hint = std.atomic.spinLoopHint;

// LOG
pub const log = std.log;

// STDIO
pub const Writer = std.io.Writer;
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
const internal_format = std.fmt.format;
const InternalFormatOptions = std.fmt.FormatOptions;

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
    runtime_assert(@src(), src.len <= dst.len);
    const dst_ptr = @ptrCast([*]u8, dst.ptr);
    const src_ptr = @ptrCast([*]const u8, src.ptr);
    const bytes_to_copy = @sizeOf(T) * src.len;
    @memcpy(dst_ptr, src_ptr, bytes_to_copy);
}

pub fn set_byte(slice: []u8, value: u8) void {
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

pub inline fn zero(bytes: []u8) void {
    set_byte(bytes, 0);
}

pub inline fn zero_slice(slice: anytype) void {
    const bytes = as_bytes(slice);
    zero(bytes);
}

pub inline fn zeroes(comptime T: type) T {
    var result: T = undefined;
    zero(as_bytes(&result));
    return result;
}

pub inline fn comptime_assert(condition: bool) void {
    if (!is_comptime()) @panic("comptime_assert called at runtime");
    if (!condition) unreachable;
}

pub inline fn runtime_assert(source_location: SourceLocation, condition: bool) void {
    if (is_comptime()) unreachable;
    if (!condition) {
        panic(source_location, "Assert failed at {s}:{}:{} {s}()", .{ source_location.file, source_location.line, source_location.column, source_location.fn_name });
    }
}

pub const MustBeExact = enum {
    must_be_exact,
    can_be_not_exact,
};

pub inline fn bytes_to_pages_extended(bytes: u64, page_size: u64, comptime must_be_exact: MustBeExact) u64 {
    return remainder_division_maybe_exact(bytes, page_size, must_be_exact);
}

pub inline fn bytes_to_sector(bytes: u64, sector_size: u64, comptime must_be_exact: MustBeExact) u64 {
    return remainder_division_maybe_exact(bytes, sector_size, must_be_exact);
}

pub inline fn bytes_to_pages(bytes: u64, page_size: u64, comptime must_be_exact: MustBeExact) u64 {
    return remainder_division_maybe_exact(bytes, page_size, must_be_exact);
}

pub inline fn remainder_division_maybe_exact(dividend: u64, divisor: u64, comptime must_be_exact: MustBeExact) u64 {
    if (divisor == 0) unreachable;
    const quotient = dividend / divisor;
    const remainder = dividend % divisor;
    const remainder_not_zero = remainder != 0;
    if (must_be_exact == .must_be_exact and remainder_not_zero) panic(@src(), "remainder not exact when asked to be exact: {} / {}", .{ dividend, divisor });

    return quotient + @boolToInt(remainder_not_zero);
}

pub fn cstr_len(cstr: [*:0]const u8) u64 {
    var len: u64 = 0;
    while (cstr[len] != 0) : (len += 1) {}
    return len;
}

pub fn Bitflag(comptime is_volatile: bool, comptime BackingType: type, comptime EnumT: type) type {
    return struct {
        pub const Enum = EnumT;
        pub const Int = BackingType;
        const EnumBitSize = @popCount(u64, @bitSizeOf(BackingType) - 1);
        comptime {
            comptime_assert(EnumBitSize == @bitSizeOf(EnumT));
        }
        const Ptr = if (is_volatile) *volatile @This() else *@This();

        bits: Int,

        pub inline fn from_flags(comptime flags: []const EnumT) @This() {
            const result = comptime blk: {
                if (flags.len > @bitSizeOf(EnumT)) @compileError("More flags than bits\n");

                comptime var bits: Int = 0;

                inline for (flags) |field| {
                    bits |= 1 << @enumToInt(field);
                }

                break :blk bits;
            };
            return @This(){ .bits = result };
        }

        pub fn from_bits(bits: Int) @This() {
            return @This(){ .bits = bits };
        }

        pub inline fn from_flag(comptime flag: EnumT) @This() {
            const bits = 1 << @enumToInt(flag);
            return @This(){ .bits = bits };
        }

        pub inline fn empty() @This() {
            return @This(){
                .bits = 0,
            };
        }

        pub inline fn all() @This() {
            var result = comptime blk: {
                var bits: Int = 0;
                inline for (@typeInfo(EnumT).Enum.fields) |field| {
                    bits |= 1 << field.value;
                }
                break :blk @This(){
                    .bits = bits,
                };
            };
            return result;
        }

        pub inline fn is_empty(self: @This()) bool {
            return self.bits == 0;
        }

        /// This assumes invalid values in the flags can't be set.
        pub inline fn is_all(self: @This()) bool {
            return all().bits == self.bits;
        }

        pub inline fn contains(self: @This(), comptime flag: EnumT) bool {
            return ((self.bits & (1 << @enumToInt(flag))) >> @enumToInt(flag)) != 0;
        }

        // TODO: create a mutable version of this
        pub inline fn or_flag(self: Ptr, comptime flag: EnumT) void {
            self.bits |= 1 << @enumToInt(flag);
        }

        pub fn format(bitflag: @This(), comptime _: []const u8, _: InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
            try writer.writeAll("{\n");
            for (enum_values(Enum)) |enum_value| {
                const bit_value = @boolToInt(bitflag.bits & (@as(Int, 1) << @intCast(u6, @enumToInt(enum_value))) != 0);
                try internal_format(writer, "\t{s}: {}\n", .{ @tagName(enum_value), bit_value });
            }
            try writer.writeAll("}");
        }
    };
}

const is_root_package_build = @hasDecl(root, "Builder");

pub fn TODO(src: SourceLocation) noreturn {
    if (@hasDecl(root, "identity")) {
        root.crash("TODO at {s}:{}:{} {s}()", .{ src.file, src.line, src.column, src.fn_name });
    } else {
        log.err("PANIC at {s}:{}:{} {s}()", .{ src.file, src.line, src.column, src.fn_name });
        unreachable;
    }
}
pub inline fn panic(src: SourceLocation, comptime message: []const u8, args: anytype) noreturn {
    if (@hasDecl(root, "identity")) {
        root.crash(message, args);
    } else {
        log.err("PANIC at {s}:{}:{} {s}()", .{ src.file, src.line, src.column, src.fn_name });
        unreachable;
    }
}

/// @Hack This currently works to determine if the code is being executed at compile time or at run time.
pub fn is_comptime() bool {
    var a: bool = false;
    return @TypeOf(@boolToInt(a)) == comptime_int;
}

pub fn test_comptime_hack() void {
    comptime {
        comptime_assert(is_comptime());
    }
    runtime_assert(@src(), !is_comptime());
}

pub const PrivilegeLevel = enum(u1) {
    kernel = 0,
    user = 1,
};

pub const File = struct {
    address: VirtualAddress,
    size: u64,
};

pub inline fn get_higher_half_map_address() u64 {
    if (@hasDecl(root, "higher_half_direct_map")) {
        return root.higher_half_direct_map;
    } else {
        @panic("can't call a non-kernel function");
    }
}
