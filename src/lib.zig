const common = @import("common.zig");
pub usingnamespace common;

pub const arch = @import("lib/arch.zig");
/// This is done so the allocator can respect allocating from different address spaces
pub const config = @import("lib/config.zig");
pub const CRC32 = @import("lib/crc32.zig");
const disk_file = @import("lib/disk.zig");
pub const Disk = disk_file.Disk;
pub const Filesystem = @import("lib/filesystem.zig");
pub const List = @import("lib/list.zig");
pub const Message = @import("lib/message.zig");
pub const NLS = @import("lib/nls.zig");
pub const PartitionTable = @import("lib/partition_table.zig");
pub const PSF1 = @import("lib/psf1.zig");
pub const Syscall = @import("lib/syscall.zig");
pub const Graphics = @import("lib/graphics.zig");
pub const Window = @import("lib/window.zig");

const extern_enum_array = @import("lib/extern_enum_array.zig");
pub const EnumArray = extern_enum_array.EnumArray;

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
                count += @boolToInt(ch == '/');
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
    return @intToPtr(*T, @ptrToInt(ptr) + @sizeOf(T) * element_offset);
}

pub inline fn maybePtrAdd(comptime T: type, ptr: ?*T, element_offset: usize) ?*T {
    return @intToPtr(*T, @ptrToInt(ptr) + @sizeOf(T) * element_offset);
}

pub inline fn ptrSub(comptime T: type, ptr: *T, element_offset: usize) *T {
    return @intToPtr(*T, @ptrToInt(ptr) - @sizeOf(T) * element_offset);
}

pub inline fn maybePtrSub(comptime T: type, ptr: ?*T, element_offset: usize) ?*T {
    return @intToPtr(*T, @ptrToInt(ptr) - @sizeOf(T) * element_offset);
}

test {
    common.log.err("asdjkasd");
    _ = DirectoryTokenizer;
    _ = Filesystem;
    _ = PartitionTable;
}

pub const Allocator = extern struct {
    callbacks: Callbacks align(8),

    pub const Allocate = struct {
        pub const Result = struct {
            address: u64,
            size: u64,
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
        const allocation_result = try allocator.callback_allocate(allocator, size, alignment);
        const result = @intToPtr([*]T, safeArchitectureCast(allocation_result.address))[0..len];
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
                    .allocate = Wrapped.wrapped_callback_allocate,
                },
            },
            .zig = .{
                .ptr = zig_allocator.ptr,
                .vtable = zig_allocator.vtable,
            },
        };
    }

    pub fn unwrap_zig(allocator: *Allocator) common.ZigAllocator {
        return .{
            .ptr = allocator,
            .vtable = &zig_vtable,
        };
    }

    pub const zig_vtable = .{
        .alloc = zig_allocate,
        .resize = zig_resize,
        .free = zig_free,
    };

    pub fn zig_allocate(context: *anyopaque, size: usize, ptr_align: u8, return_address: usize) ?[*]u8 {
        _ = context;
        _ = size;
        _ = ptr_align;
        _ = return_address;
        @panic("todo: zig_allocate");
    }
    //resize: *const fn (ctx: *anyopaque, buf: []u8, buf_align: u8, new_len: usize, ret_addr: usize) bool,
    //free: *const fn (ctx: *anyopaque, buf: []u8, buf_align: u8, ret_addr: usize) void,

    pub fn zig_resize(context: *anyopaque, buffer: []u8, buffer_alignment: u8, new_length: usize, return_address: usize) bool {
        _ = context;
        _ = buffer;
        _ = buffer_alignment;
        _ = new_length;
        _ = return_address;
        @panic("todo: zig_resize");
    }

    pub fn zig_free(context: *anyopaque, buffer: []u8, buffer_alignment: u8, return_address: usize) void {
        _ = context;
        _ = buffer;
        _ = buffer_alignment;
        _ = return_address;
        @panic("todo: zig_free");
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

        pub fn unwrap_zig(wrapped_allocator: *Wrapped) common.ZigAllocator {
            return .{
                .ptr = wrapped_allocator.zig.ptr,
                .vtable = wrapped_allocator.zig.vtable,
            };
        }

        pub fn wrapped_callback_allocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
            const wrapped_allocator = @fieldParentPtr(Wrapped, "allocator", allocator);
            const zig_allocator = wrapped_allocator.unwrap_zig();
            if (alignment > common.maxInt(u8)) {
                @panic("wtf alignment big");
            }
            const zig_result = zig_allocator.vtable.alloc(zig_allocator.ptr, size, @intCast(u8, alignment), @returnAddress());
            return .{
                .address = @ptrToInt(zig_result),
                .size = size,
            };
        }
    };
};

pub fn ELF(comptime bits: comptime_int) type {
    const is_64 = switch (bits) {
        32 => false,
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

                const file_header = @ptrCast(*const FileHeader, @alignCast(@alignOf(FileHeader), &file[0]));
                try file_header.validate();

                return Parser{
                    .file_header = file_header,
                };
            }

            pub fn getEntryPoint(parser: *const Parser) Address {
                return parser.file_header.entry_point;
            }

            pub fn getProgramHeaders(parser: *const Parser) []const ProgramHeader {
                const program_headers = @intToPtr([*]const ProgramHeader, @ptrToInt(parser.file_header) + @intCast(usize, parser.file_header.program_header_offset))[0..parser.file_header.program_header_entry_count];
                return program_headers;
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

                // TODO: further checking
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
        true => if (value <= common.maxInt(usize)) @truncate(usize, value) else @panic("safeArchitectureCast"),
        false => value,
    };
}

pub fn TargetUsize(comptime architecture: common.Target.Cpu.Arch) type {
    return switch (architecture) {
        .x86 => u32,
        .x86_64 => u64,
        else => @compileError("Architecture not supported"),
    };
}
