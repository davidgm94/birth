const common = @import("common.zig");
pub usingnamespace common;

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
pub const NLS = @import("lib/nls.zig");
pub const PartitionTable = @import("lib/partition_table.zig");
pub const QEMU = @import("lib/qemu.zig");
pub const Syscall = @import("lib/syscall.zig");
pub const Graphics = @import("lib/graphics.zig");
pub const Window = @import("lib/window.zig");

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

    test {
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
    _ = DirectoryTokenizer;
    _ = Filesystem;
    _ = PartitionTable;
}

pub const Allocator = extern struct {
    callback_allocate: *const Allocate.Fn,

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

    pub fn allocateBytes(allocator: *Allocator, size: u64, alignment: u64) Allocate.Error!Allocate.Result {
        return try allocator.callback_allocate(allocator, size, alignment);
    }

    // pub fn allocate(allocator: *Allocator, comptime T: type, len: usize) Allocate.Error![]T {
    //     _ = allocator;
    //     _ = len;
    //     @panic("WTF");
    //     // const size = @sizeOf(asdsd) * len;
    //     // const alignment = @alignOf(asdsd);
    //     // return try allocator.callback_allocate(allocator, size, alignment);
    // }

    pub fn wrap(zig_allocator: common.ZigAllocator) Wrapped {
        return .{
            .allocator = .{
                .callback_allocate = Wrapped.wrapped_callback_allocate,
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

pub const FileParser = struct {
    text: []const u8,
    index: usize = 0,

    pub fn init(text: []const u8) FileParser {
        return .{
            .text = text,
        };
    }

    const Error = error{
        err,
    };

    pub const File = struct {
        host: []const u8,
        guest: []const u8,
    };

    pub fn next(parser: *FileParser) !?File {
        while (parser.index < parser.text.len) {
            try parser.expect_char('.');
            try parser.expect_char('{');

            while (parser.index < parser.text.len and parser.text[parser.index] != '}') {
                const host_field = try parser.parse_field("host");
                const guest_field = try parser.parse_field("guest");
                return .{
                    .host = host_field,
                    .guest = guest_field,
                };
            }

            try parser.expect_char('}');
        }

        return null;
    }

    fn parse_field(parser: *FileParser, field: []const u8) ![]const u8 {
        try parser.expect_char('.');
        try parser.expect_string(field);
        try parser.expect_char('=');
        const field_value = try parser.expect_quoted_string();
        parser.maybe_expect_char(',');

        return field_value;
    }

    pub fn skip_space(parser: *FileParser) void {
        while (parser.index < parser.text.len) {
            const char = parser.text[parser.index];
            const is_space = char == ' ' or char == '\n' or char == '\r' or char == '\t';
            if (!is_space) break;
            parser.index += 1;
        }
    }

    pub fn maybe_expect_char(parser: *FileParser, char: u8) void {
        parser.skip_space();
        if (parser.text[parser.index] == char) parser.index += 1;
    }

    pub fn expect_char(parser: *FileParser, expected_char: u8) !void {
        parser.skip_space();
        const char = parser.text[parser.index];
        if (char != expected_char) {
            common.log.debug("Expected {c}, got: {c}", .{expected_char, char});
            return Error.err;
        }
        parser.index += 1;
    }

    pub fn expect_string(parser: *FileParser, string: []const u8) !void {
        parser.skip_space();
        if (!common.equal(u8, parser.text[parser.index..][0..string.len], string)) {
            return Error.err;
        }
        parser.index += string.len;
    }

    pub fn expect_quoted_string(parser: *FileParser) ![]const u8 {
        parser.skip_space();
        try parser.expect_char('"');
        const start_index = parser.index;
        while (parser.index < parser.text.len and parser.text[parser.index] != '"') {
            parser.index += 1;
        }
        const end_index = parser.index;
        try parser.expect_char('"');

        const string = parser.text[start_index..end_index];
        return string;
    }
};
