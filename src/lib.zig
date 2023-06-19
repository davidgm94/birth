const common = @import("common.zig");
pub usingnamespace common;

pub const arch = @import("lib/arch.zig");
/// This is done so the allocator can respect allocating from different address spaces
pub const config = @import("lib/config.zig");
pub const CRC32 = @import("lib/crc32.zig");
const disk_file = @import("lib/disk.zig");
pub const Disk = disk_file.Disk;
pub const Filesystem = @import("lib/filesystem.zig");
pub const NLS = @import("lib/nls.zig");
pub const PartitionTable = @import("lib/partition_table.zig");
pub const PSF1 = @import("lib/psf1.zig");
pub const Spinlock = arch.Spinlock;

const extern_enum_array = @import("lib/extern_enum_array.zig");
pub const EnumArray = extern_enum_array.EnumArray;

pub fn memcpy(noalias destination: []u8, noalias source: []const u8) void {
    @setRuntimeSafety(false);
    // Using this as the Zig implementation is really slow (at least in x86 with soft_float enabled
    // if (common.cpu.arch == .x86 or common.cpu.arch == .x86_64 and common.Target.x86.featureSetHas(common.cpu.features, .soft_float)) {
    const bytes_left = switch (common.cpu.arch) {
        .x86 => asm volatile (
            \\rep movsb
            : [ret] "={ecx}" (-> usize),
            : [dest] "{edi}" (destination.ptr),
              [src] "{esi}" (source.ptr),
              [len] "{ecx}" (source.len),
        ),
        .x86_64 => asm volatile (
            \\rep movsb
            : [ret] "={rcx}" (-> usize),
            : [dest] "{rdi}" (destination.ptr),
              [src] "{rsi}" (source.ptr),
              [len] "{rcx}" (source.len),
        ),
        else => @compileError("Unreachable"),
    };

    common.assert(bytes_left == 0);
    // } else {
    //     @memcpy(destination, source);
    // }
}

// pub fn memset(comptime T: type, slice: []T, elem: T) void {
//     @setRuntimeSafety(false);
//
//     const bytes_left = switch (T) {
//         u8 => switch (common.cpu.arch) {
//             .x86 => asm volatile (
//                 \\rep stosb
//                 : [ret] "={ecx}" (-> usize),
//                 : [slice] "{edi}" (slice.ptr),
//                   [len] "{ecx}" (slice.len),
//                   [element] "{al}" (elem),
//             ),
//             .x86_64 => asm volatile (
//                 \\rep movsb
//                 : [ret] "={rcx}" (-> usize),
//                 : [slice] "{rdi}" (slice.ptr),
//                   [len] "{rcx}" (slice.len),
//                   [element] "{al}" (elem),
//             ),
//             else => @compileError("Unsupported OS"),
//         },
//         else => @compileError("Type " ++ @typeName(T) ++ " not supported"),
//     };
//
//     common.assert(bytes_left == 0);
// }

pub fn EnumStruct(comptime Enum: type, comptime Value: type) type {
    const EnumFields = common.enumFields(Enum);
    const MyEnumStruct = @Type(.{
        .Struct = .{
            .layout = .Extern,
            .fields = &blk: {
                var arr = [1]common.Type.StructField{undefined} ** EnumFields.len;
                inline for (EnumFields) |EnumValue| {
                    arr[EnumValue.value] = .{
                        .name = EnumValue.name,
                        .type = Value,
                        .default_value = null,
                        .is_comptime = false,
                        .alignment = @alignOf(Value),
                    };
                }
                break :blk arr;
            },
            .decls = &.{},
            .is_tuple = false,
        },
    });
    const MyEnumArray = EnumArray(Enum, Value);
    const Union = extern union {
        fields: Struct,
        array: Array,

        pub const Struct = MyEnumStruct;
        pub const Array = MyEnumArray;
    };

    common.assert(@sizeOf(Union.Struct) == @sizeOf(Union.Array));
    common.assert(@sizeOf(Union.Array) == @sizeOf(Union));

    return Union;
}

pub const DirectoryTokenizer = struct {
    string: []const u8,
    index: usize = 0,
    given_count: usize = 0,
    total_count: usize,

    pub fn init(string: []const u8) DirectoryTokenizer {
        common.assert(string.len > 0);
        var count: usize = 0;

        if (string[0] == '/') {
            for (string) |ch| {
                count += @intFromBool(ch == '/');
            }
        } else unreachable;

        return .{ .string = string, .total_count = count + 1 };
    }

    pub fn next(tokenizer: *DirectoryTokenizer) ?[]const u8 {
        if (tokenizer.index == 0) {
            const is_root_dir = tokenizer.string[0] == '/';
            if (is_root_dir) {
                tokenizer.index += 1;
                tokenizer.given_count += 1;
                return "/";
            } else unreachable;
        } else {
            const original_index = tokenizer.index;
            if (original_index < tokenizer.string.len) {
                for (tokenizer.string[original_index..]) |char| {
                    if (char == '/') {
                        const result = tokenizer.string[original_index..tokenizer.index];
                        tokenizer.given_count += 1;
                        tokenizer.index += 1;
                        return result;
                    }

                    tokenizer.index += 1;
                }

                tokenizer.given_count += 1;

                return tokenizer.string[original_index..];
            } else {
                common.assert(original_index == tokenizer.string.len);
                common.assert(tokenizer.given_count == tokenizer.total_count);
                return null;
            }
        }
    }

    pub fn is_last(tokenizer: DirectoryTokenizer) bool {
        return tokenizer.given_count == tokenizer.total_count;
    }

    test "directory tokenizer" {
        common.log.err("ajskdjsa", .{});
        if (common.os != .freestanding) {
            const TestCase = struct {
                path: []const u8,
                expected_result: []const []const u8,
            };

            const test_cases = [_]TestCase{
                .{ .path = "/EFI", .expected_result = &.{ "/", "EFI" } },
                .{ .path = "/abc/def/a", .expected_result = &.{ "/", "abc", "def", "a" } },
            };

            inline for (test_cases) |case| {
                var dir_tokenizer = DirectoryTokenizer.init(case.path);
                var results: [case.expected_result.len][]const u8 = undefined;
                var result_count: usize = 0;

                while (dir_tokenizer.next()) |dir| {
                    try common.testing.expect(result_count < results.len);
                    try common.testing.expectEqualStrings(case.expected_result[result_count], dir);
                    results[result_count] = dir;
                    result_count += 1;
                }

                try common.testing.expectEqual(case.expected_result.len, result_count);
            }
        }
    }
};

pub inline fn ptrAdd(comptime T: type, ptr: *T, element_offset: usize) *T {
    return @as(*T, @ptrFromInt(@intFromPtr(ptr) + @sizeOf(T) * element_offset));
}

pub inline fn maybePtrAdd(comptime T: type, ptr: ?*T, element_offset: usize) ?*T {
    return @as(*T, @ptrFromInt(@intFromPtr(ptr) + @sizeOf(T) * element_offset));
}

pub inline fn ptrSub(comptime T: type, ptr: *T, element_offset: usize) *T {
    return @as(*T, @ptrFromInt(@intFromPtr(ptr) - @sizeOf(T) * element_offset));
}

pub inline fn maybePtrSub(comptime T: type, ptr: ?*T, element_offset: usize) ?*T {
    return @as(*T, @ptrFromInt(@intFromPtr(ptr) - @sizeOf(T) * element_offset));
}

test {
    common.log.err("test not taken into the test suite");
    _ = DirectoryTokenizer;
    _ = Filesystem;
    _ = PartitionTable;
}

pub const Allocator = extern struct {
    callbacks: Callbacks align(8),

    pub const Allocate = struct {
        pub const Result = extern struct {
            address: u64,
            size: u64,

            pub fn toBytes(result: Result) []u8 {
                return @as([*]u8, @ptrFromInt(result.address))[0..result.size];
            }
        };
        pub const Fn = fn (allocator: *Allocator, size: u64, alignment: u64) Error!Result;
        pub const Error = error{
            OutOfMemory,
        };
    };

    /// Necessary to do this hack
    const Callbacks = switch (common.cpu.arch) {
        .x86 => extern struct {
            allocate: *const Allocate.Fn,
            allocate_padding: u32 = 0,
        },
        .x86_64, .aarch64, .riscv64 => extern struct {
            allocate: *const Allocate.Fn,
        },
        else => @compileError("Architecture not supported"),
    };

    pub inline fn allocateBytes(allocator: *Allocator, size: u64, alignment: u64) Allocate.Error!Allocate.Result {
        return try allocator.callbacks.allocate(allocator, size, alignment);
    }

    pub inline fn allocate(allocator: *Allocator, comptime T: type, len: usize) Allocate.Error![]T {
        const size = @sizeOf(T) * len;
        const alignment = @alignOf(T);
        const allocation_result = try allocator.callbacks.allocate(allocator, size, alignment);
        const result = @as([*]T, @ptrFromInt(safeArchitectureCast(allocation_result.address)))[0..len];
        return result;
    }

    pub inline fn create(allocator: *Allocator, comptime T: type) Allocate.Error!*T {
        const result = try allocator.allocate(T, 1);
        return &result[0];
    }

    pub fn wrap(zig_allocator: common.ZigAllocator) Wrapped {
        return .{
            .allocator = .{
                .callbacks = .{
                    .allocate = Wrapped.wrappedCallbackAllocate,
                },
            },
            .zig = .{
                .ptr = zig_allocator.ptr,
                .vtable = zig_allocator.vtable,
            },
        };
    }

    pub fn zigUnwrap(allocator: *Allocator) common.ZigAllocator {
        return .{
            .ptr = allocator,
            .vtable = &zig_vtable,
        };
    }

    pub const zig_vtable = .{
        .alloc = zigAllocate,
        .resize = zigResize,
        .free = zigFree,
    };

    pub fn zigAllocate(context: *anyopaque, size: usize, ptr_align: u8, return_address: usize) ?[*]u8 {
        _ = context;
        _ = size;
        _ = ptr_align;
        _ = return_address;
        return null;
    }

    pub fn zigResize(context: *anyopaque, buffer: []u8, buffer_alignment: u8, new_length: usize, return_address: usize) bool {
        _ = context;
        _ = buffer;
        _ = buffer_alignment;
        _ = new_length;
        _ = return_address;
        return false;
    }

    pub fn zigFree(context: *anyopaque, buffer: []u8, buffer_alignment: u8, return_address: usize) void {
        _ = context;
        _ = buffer;
        _ = buffer_alignment;
        _ = return_address;
    }

    pub const Wrapped = extern struct {
        allocator: Allocator,
        zig: extern struct {
            ptr: *anyopaque,
            vtable: *const common.ZigAllocator.VTable,
        },

        pub fn unwrap(wrapped_allocator: *Wrapped) *Allocator {
            return &wrapped_allocator.allocator;
        }

        pub fn zigUnwrap(wrapped_allocator: *Wrapped) common.ZigAllocator {
            return .{
                .ptr = wrapped_allocator.zig.ptr,
                .vtable = wrapped_allocator.zig.vtable,
            };
        }

        pub fn wrappedCallbackAllocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
            const wrapped_allocator = @fieldParentPtr(Wrapped, "allocator", allocator);
            const zig_allocator = wrapped_allocator.zigUnwrap();
            if (alignment > common.maxInt(u8)) {
                @panic("alignment supported by Zig is less than asked");
            }
            const zig_result = zig_allocator.vtable.alloc(zig_allocator.ptr, size, @as(u8, @intCast(alignment)), @returnAddress());
            return .{
                .address = @intFromPtr(zig_result),
                .size = size,
            };
        }
    };
};

pub fn ELF(comptime bits: comptime_int) type {
    const is_64 = switch (bits) {
        32 => @compileError("ELF file is not supported"),
        64 => true,
        else => @compileError("ELF is not supported for those bits"),
    };

    return struct {
        const Address = if (is_64) u64 else u32;

        pub const Parser = struct {
            file_header: *const FileHeader,

            pub fn init(file: []const u8) Error!Parser {
                if (file.len < @sizeOf(FileHeader)) {
                    return Error.not_long_enough;
                }

                const file_header: *const FileHeader = @ptrCast(@alignCast(&file[0]));
                try file_header.validate();

                return Parser{
                    .file_header = file_header,
                };
            }

            pub fn getEntryPoint(parser: *const Parser) Address {
                return parser.file_header.entry_point;
            }

            pub fn getProgramHeaders(parser: *const Parser) []const ProgramHeader {
                const program_headers = @as([*]const ProgramHeader, @ptrFromInt(@intFromPtr(parser.file_header) + @as(usize, @intCast(parser.file_header.program_header_offset))))[0..parser.file_header.program_header_entry_count];
                return program_headers;
            }

            pub fn getSectionHeaders(parser: *const Parser) []const SectionHeader {
                const section_headers = @as([*]const SectionHeader, @ptrFromInt(@intFromPtr(parser.file_header) + @as(usize, @intCast(parser.file_header.section_header_offset))))[0..parser.file_header.section_header_entry_count];
                return section_headers;
            }

            pub const Error = error{
                not_long_enough,
                invalid_magic,
                invalid_signature,
                invalid_bits,
                weird_program_header_size,
                weird_section_header_size,
            };
        };

        pub const FileHeader = switch (is_64) {
            true => extern struct {
                // e_ident
                magic: u8 = magic,
                elf_id: [3]u8 = elf_signature.*,
                bit_count: Bits = .b64,
                endianness: Endianness = .little,
                header_version: u8 = 1,
                os_abi: ABI = .SystemV,
                abi_version: u8 = 0,
                padding: [7]u8 = [_]u8{0} ** 7,
                object_type: ObjectFileType = .executable, // e_type
                machine: Machine = .AMD64,
                version: u32 = 1,
                entry_point: u64,
                program_header_offset: u64 = 0x40,
                section_header_offset: u64,
                flags: u32 = 0,
                header_size: u16 = 0x40,
                program_header_size: u16 = @sizeOf(ProgramHeader),
                program_header_entry_count: u16 = 1,
                section_header_size: u16 = @sizeOf(SectionHeader),
                section_header_entry_count: u16,
                name_section_header_index: u16,

                const magic = 0x7f;
                const elf_signature = "ELF";
                const Bits = enum(u8) {
                    b32 = 1,
                    b64 = 2,
                };

                const Endianness = enum(u8) {
                    little = 1,
                    big = 2,
                };

                const ABI = enum(u8) {
                    SystemV = 0,
                };

                pub const ObjectFileType = enum(u16) {
                    none = 0,
                    relocatable = 1,
                    executable = 2,
                    dynamic = 3,
                    core = 4,
                    lo_os = 0xfe00,
                    hi_os = 0xfeff,
                    lo_proc = 0xff00,
                    hi_proc = 0xffff,
                };

                pub const Machine = enum(u16) {
                    AMD64 = 0x3e,
                };

                pub fn validate(file_header: *const FileHeader) Parser.Error!void {
                    if (file_header.magic != FileHeader.magic) {
                        return Parser.Error.invalid_magic;
                    }

                    if (!common.equal(u8, &file_header.elf_id, FileHeader.elf_signature)) {
                        return Parser.Error.invalid_signature;
                    }

                    switch (file_header.bit_count) {
                        .b32 => if (bits != 32) return Parser.Error.invalid_bits,
                        .b64 => if (bits != 64) return Parser.Error.invalid_bits,
                    }

                    if (file_header.program_header_size != @sizeOf(ProgramHeader)) {
                        return Parser.Error.weird_program_header_size;
                    }

                    if (file_header.section_header_size != @sizeOf(SectionHeader)) {
                        return Parser.Error.weird_section_header_size;
                    }
                }
            },
            false => @compileError("Not yet supported"),
        };

        pub const ProgramHeader = switch (is_64) {
            true => extern struct {
                type: Type = .load,
                flags: Flags, //= @enumToInt(Flags.readable) | @enumToInt(Flags.executable),
                offset: u64,
                virtual_address: u64,
                physical_address: u64,
                size_in_file: u64,
                size_in_memory: u64,
                alignment: u64 = 0,

                const Type = enum(u32) {
                    null = 0,
                    load = 1,
                    dynamic = 2,
                    interpreter = 3,
                    note = 4,
                    shlib = 5, // reserved
                    program_header = 6,
                    tls = 7,
                    lo_os = 0x60000000,
                    gnu_eh_frame = 0x6474e550,
                    gnu_stack = 0x6474e551,
                    hi_os = 0x6fffffff,
                    lo_proc = 0x70000000,
                    hi_proc = 0x7fffffff,
                    _,
                };

                const Flags = packed struct {
                    executable: bool,
                    writable: bool,
                    readable: bool,
                    reserved: u29,

                    comptime {
                        common.assert(@sizeOf(Flags) == @sizeOf(u32));
                    }
                };
            },
            false => @compileError("Not yet supported"),
        };
        pub const SectionHeader = switch (is_64) {
            true => extern struct {
                name_offset: u32,
                type: u32,
                flags: u64,
                address: u64,
                offset: u64,
                size: u64,
                // section index
                link: u32,
                info: u32,
                alignment: u64,
                entry_size: u64,

                // type
                const ID = enum(u32) {
                    null = 0,
                    program_data = 1,
                    symbol_table = 2,
                    string_table = 3,
                    relocation_entries_addends = 4,
                    symbol_hash_table = 5,
                    dynamic_linking_info = 6,
                    notes = 7,
                    program_space_no_data = 8,
                    relocation_entries = 9,
                    reserved = 10,
                    dynamic_linker_symbol_table = 11,
                    array_of_constructors = 14,
                    array_of_destructors = 15,
                    array_of_pre_constructors = 16,
                    section_group = 17,
                    extended_section_indices = 18,
                    number_of_defined_types = 19,
                    start_os_specific = 0x60000000,
                };

                const Flag = enum(u64) {
                    writable = 0x01,
                    alloc = 0x02,
                    executable = 0x04,
                    mergeable = 0x10,
                    contains_null_terminated_strings = 0x20,
                    info_link = 0x40,
                    link_order = 0x80,
                    os_non_conforming = 0x100,
                    section_group = 0x200,
                    tls = 0x400,
                    mask_os = 0x0ff00000,
                    mask_processor = 0xf0000000,
                    ordered = 0x4000000,
                    exclude = 0x8000000,
                };
            },
            false => @compileError("Not yet supported"),
        };
    };
}

pub inline fn safeArchitectureCast(value: anytype) usize {
    return switch (@sizeOf(@TypeOf(value)) > @sizeOf(usize)) {
        true => if (value <= common.maxInt(usize)) @as(usize, @truncate(value)) else {
            common.log.err("PANIC: virtual address is longer than usize: 0x{x}", .{value});
            @panic("safeArchitectureCast");
        },
        false => value,
    };
}

pub const DereferenceError = error{
    address_bigger_than_usize,
};

pub inline fn tryDereferenceAddress(value: anytype) DereferenceError!usize {
    common.assert(@sizeOf(@TypeOf(value)) > @sizeOf(usize));
    return if (value <= common.maxInt(usize)) @as(usize, @truncate(value)) else return DereferenceError.address_bigger_than_usize;
}

pub fn enumAddNames(comptime enum_fields: []const common.Type.EnumField, comptime names: []const []const u8) []const common.Type.EnumField {
    comptime var result = enum_fields;
    const previous_last_value = if (enum_fields.len > 0) enum_fields[enum_fields.len - 1].value else 0;

    inline for (names, 0..) |name, value_start| {
        const value = value_start + previous_last_value;
        result = result ++ .{.{
            .name = name,
            .value = value,
        }};
    }

    return result;
}

pub fn ErrorSet(comptime error_names: []const []const u8, comptime predefined_fields: []const common.Type.EnumField) type {
    comptime var error_fields: []const common.Type.Error = &.{};
    comptime var enum_items: []const common.Type.EnumField = predefined_fields;
    comptime var enum_value = enum_items[enum_items.len - 1].value + 1;

    inline for (error_names) |error_name| {
        enum_items = enum_items ++ [1]common.Type.EnumField{
            .{
                .name = error_name,
                .value = enum_value,
            },
        };

        enum_value += 1;
    }

    inline for (enum_items) |item| {
        error_fields = error_fields ++ [1]common.Type.Error{
            .{
                .name = item.name,
            },
        };
    }

    const EnumType = @Type(common.Type{
        .Enum = .{
            .tag_type = u16,
            .fields = enum_items,
            .decls = &.{},
            .is_exhaustive = true,
        },
    });

    const ErrorType = @Type(common.Type{
        .ErrorSet = error_fields,
    });

    return struct {
        pub const Error = ErrorType;
        pub const Enum = EnumType;
    };
}

pub fn getDebugInformation(allocator: common.ZigAllocator, elf_file: []align(common.default_sector_size) const u8) !common.ModuleDebugInfo {
    const elf = common.elf;
    var module_debug_info: common.ModuleDebugInfo = undefined;
    _ = module_debug_info;
    const hdr = @as(*const elf.Ehdr, @ptrCast(&elf_file[0]));
    if (!common.equal(u8, hdr.e_ident[0..4], elf.MAGIC)) return error.InvalidElfMagic;
    if (hdr.e_ident[elf.EI_VERSION] != 1) return error.InvalidElfVersion;

    const endian = .Little;

    const shoff = hdr.e_shoff;
    const str_section_off = shoff + @as(u64, hdr.e_shentsize) * @as(u64, hdr.e_shstrndx);
    const str_shdr = @as(
        *const elf.Shdr,
        @ptrCast(@alignCast(&elf_file[common.cast(usize, str_section_off) orelse return error.Overflow])),
    );
    const header_strings = elf_file[str_shdr.sh_offset .. str_shdr.sh_offset + str_shdr.sh_size];
    const shdrs = @as(
        [*]const elf.Shdr,
        @ptrCast(@alignCast(&elf_file[shoff])),
    )[0..hdr.e_shnum];

    var opt_debug_info: ?[]const u8 = null;
    var opt_debug_abbrev: ?[]const u8 = null;
    var opt_debug_str: ?[]const u8 = null;
    var opt_debug_str_offsets: ?[]const u8 = null;
    var opt_debug_line: ?[]const u8 = null;
    var opt_debug_line_str: ?[]const u8 = null;
    var opt_debug_ranges: ?[]const u8 = null;
    var opt_debug_loclists: ?[]const u8 = null;
    var opt_debug_rnglists: ?[]const u8 = null;
    var opt_debug_addr: ?[]const u8 = null;
    var opt_debug_names: ?[]const u8 = null;
    var opt_debug_frame: ?[]const u8 = null;

    for (shdrs) |*shdr| {
        if (shdr.sh_type == elf.SHT_NULL) continue;

        const name = common.sliceTo(header_strings[shdr.sh_name..], 0);
        if (common.equal(u8, name, ".debug_info")) {
            opt_debug_info = try chopSlice(elf_file, shdr.sh_offset, shdr.sh_size);
        } else if (common.equal(u8, name, ".debug_abbrev")) {
            opt_debug_abbrev = try chopSlice(elf_file, shdr.sh_offset, shdr.sh_size);
        } else if (common.equal(u8, name, ".debug_str")) {
            opt_debug_str = try chopSlice(elf_file, shdr.sh_offset, shdr.sh_size);
        } else if (common.equal(u8, name, ".debug_str_offsets")) {
            opt_debug_str_offsets = try chopSlice(elf_file, shdr.sh_offset, shdr.sh_size);
        } else if (common.equal(u8, name, ".debug_line")) {
            opt_debug_line = try chopSlice(elf_file, shdr.sh_offset, shdr.sh_size);
        } else if (common.equal(u8, name, ".debug_line_str")) {
            opt_debug_line_str = try chopSlice(elf_file, shdr.sh_offset, shdr.sh_size);
        } else if (common.equal(u8, name, ".debug_ranges")) {
            opt_debug_ranges = try chopSlice(elf_file, shdr.sh_offset, shdr.sh_size);
        } else if (common.equal(u8, name, ".debug_loclists")) {
            opt_debug_loclists = try chopSlice(elf_file, shdr.sh_offset, shdr.sh_size);
        } else if (common.equal(u8, name, ".debug_rnglists")) {
            opt_debug_rnglists = try chopSlice(elf_file, shdr.sh_offset, shdr.sh_size);
        } else if (common.equal(u8, name, ".debug_addr")) {
            opt_debug_addr = try chopSlice(elf_file, shdr.sh_offset, shdr.sh_size);
        } else if (common.equal(u8, name, ".debug_names")) {
            opt_debug_names = try chopSlice(elf_file, shdr.sh_offset, shdr.sh_size);
        } else if (common.equal(u8, name, ".debug_frame")) {
            opt_debug_frame = try chopSlice(elf_file, shdr.sh_offset, shdr.sh_size);
        }
    }

    var di = common.dwarf.DwarfInfo{
        .endian = endian,
        .debug_info = opt_debug_info orelse return error.MissingDebugInfo,
        .debug_abbrev = opt_debug_abbrev orelse return error.MissingDebugInfo,
        .debug_str = opt_debug_str orelse return error.MissingDebugInfo,
        .debug_str_offsets = opt_debug_str_offsets,
        .debug_line = opt_debug_line orelse return error.MissingDebugInfo,
        .debug_line_str = opt_debug_line_str,
        .debug_ranges = opt_debug_ranges,
        .debug_loclists = opt_debug_loclists,
        .debug_rnglists = opt_debug_rnglists,
        .debug_addr = opt_debug_addr,
        .debug_names = opt_debug_names,
        .debug_frame = opt_debug_frame,
    };

    try common.dwarf.openDwarfDebugInfo(&di, allocator);
    return di;
}

fn chopSlice(ptr: []const u8, offset: u64, size: u64) error{Overflow}![]const u8 {
    const start = common.cast(usize, offset) orelse return error.Overflow;
    const end = start + (common.cast(usize, size) orelse return error.Overflow);
    return ptr[start..end];
}

pub fn RegionInterface(comptime Region: type) type {
    const type_info = @typeInfo(Region);
    common.assert(type_info == .Struct);
    common.assert(type_info.Struct.layout == .Extern);
    common.assert(type_info.Struct.fields.len == 2);
    const fields = type_info.Struct.fields;
    common.assert(common.equal(u8, fields[0].name, "address"));
    common.assert(common.equal(u8, fields[1].name, "size"));
    const Addr = fields[0].type;
    const AddrT = getAddrT(Addr);

    return struct {
        pub inline fn new(info: struct {
            address: Addr,
            size: AddrT,
        }) Region {
            return Region{
                .address = info.address,
                .size = info.size,
            };
        }
        pub inline fn fromRaw(info: struct {
            raw_address: AddrT,
            size: AddrT,
        }) Region {
            const address = Addr.new(info.raw_address);
            return new(.{
                .address = address,
                .size = info.size,
            });
        }

        pub inline fn fromAllocation(info: struct {
            allocation: Allocator.Allocate.Result,
        }) Region {
            return new(.{
                .address = addressToAddrT(info.allocation.address),
                .size = info.allocation.size,
            });
        }

        inline fn addressToAddrT(address: AddrT) Addr {
            return if (Region == PhysicalMemoryRegion and address >= config.cpu_driver_higher_half_address) VirtualAddress.new(address).toPhysicalAddress() else Addr.new(address);
        }

        pub inline fn fromByteSlice(info: struct {
            slice: []const u8,
        }) Region {
            return new(.{
                .address = addressToAddrT(@intFromPtr(info.slice.ptr)),
                .size = info.slice.len,
            });
        }

        pub inline fn fromAnytype(any: anytype, info: struct {}) Region {
            _ = info;
            common.assert(@typeInfo(@TypeOf(any)) == .Pointer);
            return Region{
                .address = VirtualAddress.new(@intFromPtr(any)),
                .size = @sizeOf(@TypeOf(any.*)),
            };
        }

        pub inline fn offset(region: Region, asked_offset: AddrT) Region {
            const address = region.address.offset(asked_offset);
            const size = region.size - asked_offset;
            return Region{
                .address = address,
                .size = size,
            };
        }

        pub inline fn addOffset(region: *Region, asked_offset: AddrT) void {
            region.* = region.offset(asked_offset);
        }

        pub inline fn top(region: Region) Addr {
            return region.address.offset(region.size);
        }

        pub fn shrinked(region: Region, size: AddrT) Region {
            common.assert(size <= region.size);
            const result = Region{
                .address = region.address,
                .size = size,
            };

            return result;
        }

        pub inline fn takeSlice(region: *Region, size: AddrT) Region {
            common.assert(size <= region.size);
            const result = Region{
                .address = region.address,
                .size = size,
            };
            region.* = region.offset(size);

            return result;
        }

        pub inline fn split(region: Region, comptime count: comptime_int) [count]Region {
            const region_size = @divExact(region.size, count);
            var result: [count]Region = undefined;
            var address = region.address;
            var region_offset: u64 = 0;
            inline for (&result) |*split_region| {
                split_region.* = Region{
                    .address = address.offset(region_offset),
                    .size = region_size,
                };
                region_offset += region_size;
            }

            return result;
        }
    };
}

pub const PhysicalMemoryRegion = extern struct {
    address: PhysicalAddress,
    size: u64,

    pub usingnamespace RegionInterface(@This()); // This is so cool

    pub inline fn toIdentityMappedVirtualAddress(physical_memory_region: PhysicalMemoryRegion) VirtualMemoryRegion {
        return .{
            .address = physical_memory_region.address.toIdentityMappedVirtualAddress(),
            .size = physical_memory_region.size,
        };
    }

    pub inline fn toHigherHalfVirtualAddress(physical_memory_region: PhysicalMemoryRegion) VirtualMemoryRegion {
        return .{
            .address = physical_memory_region.address.toHigherHalfVirtualAddress(),
            .size = physical_memory_region.size,
        };
    }
};

pub const VirtualMemoryRegion = extern struct {
    address: VirtualAddress,
    size: u64,

    pub usingnamespace RegionInterface(@This());

    pub inline fn access(virtual_memory_region: VirtualMemoryRegion, comptime T: type) []T {
        const slice_len = @divExact(virtual_memory_region.size, @sizeOf(T));
        const result = virtual_memory_region.address.access([*]T)[0..safeArchitectureCast(slice_len)];
        return result;
    }

    pub inline fn takeByteSlice(virtual_memory_region: *VirtualMemoryRegion, size: u64) []u8 {
        return virtual_memory_region.takeSlice(size).access(u8);
    }

    pub inline fn toPhysicalAddress(virtual_memory_region: VirtualMemoryRegion, info: struct {}) PhysicalMemoryRegion {
        _ = info;
        return PhysicalMemoryRegion{
            .address = virtual_memory_region.address.toPhysicalAddress(),
            .size = virtual_memory_region.size,
        };
    }
};

fn getAddrT(comptime AddressEnum: type) type {
    const type_info = @typeInfo(AddressEnum);
    common.assert(type_info == .Enum);
    const AddrT = type_info.Enum.tag_type;
    common.assert(switch (common.cpu.arch) {
        .x86 => @sizeOf(AddrT) == 2 * @sizeOf(usize),
        else => @sizeOf(AddrT) == @sizeOf(usize),
    });

    return AddrT;
}

pub fn AddressInterface(comptime AddressEnum: type) type {
    const Addr = AddressEnum;
    const AddrT = getAddrT(AddressEnum);

    const Result = struct {
        pub inline fn newNoChecks(addr: AddrT) Addr {
            return @as(Addr, @enumFromInt(addr));
        }

        pub inline fn invalid() Addr {
            return newNoChecks(0);
        }

        pub inline fn value(addr: Addr) AddrT {
            return @intFromEnum(addr);
        }

        pub inline fn offset(addr: Addr, asked_offset: AddrT) Addr {
            return newNoChecks(addr.value() + asked_offset);
        }

        pub inline fn negativeOffset(addr: Addr, asked_offset: AddrT) Addr {
            return newNoChecks(addr.value() - asked_offset);
        }

        pub inline fn addOffset(addr: *Addr, asked_offset: AddrT) void {
            addr.* = addr.offset(asked_offset);
        }

        pub inline fn subOffset(addr: *Addr, asked_offset: AddrT) void {
            addr.* = addr.negativeOffset(asked_offset);
        }

        pub inline fn isAligned(addr: Addr, alignment: u64) bool {
            const alignment_mask = alignment - 1;
            return addr.value() & alignment_mask == 0;
        }
    };

    return Result;
}

pub const PhysicalAddress = enum(u64) {
    null = 0,
    _,
    const PA = @This();

    pub usingnamespace AddressInterface(@This());

    pub inline fn new(address: u64) PA {
        if (address >= config.cpu_driver_higher_half_address) @panic("Trying to write a higher half virtual address value into a physical address");
        return @as(PA, @enumFromInt(address));
    }

    pub inline fn toIdentityMappedVirtualAddress(physical_address: PA) VirtualAddress {
        return VirtualAddress.new(physical_address.value());
    }

    pub inline fn toHigherHalfVirtualAddress(physical_address: PA) VirtualAddress {
        return physical_address.toIdentityMappedVirtualAddress().offset(config.cpu_driver_higher_half_address);
    }
};

pub const VirtualAddress = enum(u64) {
    null = 0,
    _,

    pub usingnamespace AddressInterface(@This());

    pub inline fn new(address: anytype) VirtualAddress {
        const T = @TypeOf(address);
        return @as(VirtualAddress, @enumFromInt(switch (T) {
            usize, u64, comptime_int => address,
            else => switch (@typeInfo(T)) {
                .Fn => @intFromPtr(&address),
                .Pointer => @intFromPtr(address),
                else => {
                    @compileLog(T);
                    @compileError("HA!");
                },
            },
        }));
    }

    pub inline fn access(virtual_address: VirtualAddress, comptime Ptr: type) Ptr {
        return @as(Ptr, @ptrFromInt(safeArchitectureCast(virtual_address.value())));
    }

    pub inline fn isValid(virtual_address: VirtualAddress) bool {
        _ = virtual_address;
        return true;
    }

    pub inline fn toPhysicalAddress(virtual_address: VirtualAddress) PhysicalAddress {
        common.assert(virtual_address.value() >= config.cpu_driver_higher_half_address);
        return @as(PhysicalAddress, @enumFromInt(virtual_address.value() - config.cpu_driver_higher_half_address));
    }

    pub inline fn toGuaranteedPhysicalAddress(virtual_address: VirtualAddress) PhysicalAddress {
        common.assert(virtual_address.value() < config.cpu_driver_higher_half_address);
        return PhysicalAddress.new(virtual_address.value());
    }
};

pub const Color = enum {
    black,
    red,
    green,
    yellow,
    blue,
    magenta,
    cyan,
    white,
    bright_black,
    bright_red,
    bright_green,
    bright_yellow,
    bright_blue,
    bright_magenta,
    bright_cyan,
    bright_white,
    dim,
    bold,
    reset,

    pub fn get(color: Color) []const u8 {
        return switch (color) {
            .black => "\x1b[30m",
            .red => "\x1b[31m",
            .green => "\x1b[32m",
            .yellow => "\x1b[33m",
            .blue => "\x1b[34m",
            .magenta => "\x1b[35m",
            .cyan => "\x1b[36m",
            .white => "\x1b[37m",
            .bright_black => "\x1b[90m",
            .bright_red => "\x1b[91m",
            .bright_green => "\x1b[92m",
            .bright_yellow => "\x1b[93m",
            .bright_blue => "\x1b[94m",
            .bright_magenta => "\x1b[95m",
            .bright_cyan => "\x1b[96m",
            .bright_white => "\x1b[97m",
            .bold => "\x1b[1m",
            .dim => "\x1b[2m",
            .reset => "\x1b[0m",
        };
    }
};
