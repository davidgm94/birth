pub const arch = @import("arch/x86_64.zig");
pub const bootloader = @import("bootloader.zig");
pub const stivale = @import("stivale");

const std = @import("std");

pub const LocalStorage = struct
{
    arch: arch.LocalStorage,
};

pub fn log(str: []const u8) void
{
    if (@ptrToInt(bootloader.info.terminal_callback) != 0)
    {
        bootloader.info.terminal_callback(str.ptr, str.len);
    }
    arch.write_to_debug_port(str);
}

fn log_format(format_buffer: []u8, comptime format: []const u8, args: anytype) callconv(.Inline) []u8
{
    return std.fmt.bufPrint(format_buffer, format, args) catch @panic("unable to format log call");
}

var log_format_buffer: [0x4000]u8 align(0x1000) = undefined;
pub fn logf(comptime format: []const u8, args: anytype) void
{
    const formatted_slice = log_format(&log_format_buffer, format, args);
    log(formatted_slice);
}

// @TODO: turn off interrupts
var panic_format_buffer: [0x4000]u8 align(0x1000) = undefined;
pub fn panic(comptime format: []const u8, args: anytype) noreturn
{
    const formatted_slice = log_format(&panic_format_buffer, format, args);
    log(formatted_slice);
    arch.spin();
}

pub fn assert(condition: bool, src: std.builtin.SourceLocation) void
{
    if (!condition) panic("Assert failed at {s}:{}:{} {s}()\n", .{src.file, src.line, src.column, src.fn_name});
}

pub const MemoryRegion = struct
{
    address: u64,
    size: u64,
};

export fn _start(info: *align(1) stivale.Struct) callconv(.C) noreturn
{
    stivale.parse_tags(info);
    main();
}

const PhysicalAllocator = struct
{
    const sizes = [_]u64
    {
        1 << 12,
        1 << 13,
        1 << 14,
        1 << 15,
        1 << 16,
        1 << 17,
        1 << 18,
        1 << 19,
        1 << 20,
        1 << 21,
        1 << 22,
        1 << 23,
        1 << 24,
        1 << 25,
        1 << 26,
        1 << 27,
        1 << 28,
        1 << 29,
        1 << 30,
        1 << 31,
        1 << 32,
        1 << 33,
        1 << 34,
        1 << 35,
        1 << 36,
        1 << 37,
        1 << 38,
        1 << 39,
        1 << 40,
        1 << 41,
        1 << 42,
        1 << 43,
        1 << 44,
        1 << 45,
        1 << 46,
        1 << 47,
        1 << 48,
        1 << 49,
        1 << 50,
        1 << 51,
        1 << 52,
        1 << 53,
        1 << 54,
        1 << 55,
        1 << 56,
        1 << 57,
        1 << 58,
        1 << 59,
        1 << 60,
    };

    const reverse_sizes = blk:
    {
        var result = sizes;
        std.mem.reverse(u64, result);
        break :blk result;
    };

    var free_roots: [sizes.len]u64 = undefined;

    fn free(physical_address: u64, index: u64) void
    {
        const last = free_roots[index];
        free_roots[index] = physical_address;
    }
};

var physical_allocator: PhysicalAllocator = undefined;

fn is_aligned(value: u64, alignment: u64) bool
{
    const mask = alignment - 1;
    return (value & mask) == 0;
}

pub fn main() noreturn
{
    log("Welcome to the RNU kernel!\n");
    arch.init();

    for (bootloader.info.memory_map_entries[0..bootloader.info.memory_map_entry_count]) |*entry|
    {
        var region_address = entry.address;
        var region_size = entry.size;

        while (region_size != 0)
        {
            for (reverse_sizes) |pmm_size, reverse_i|
            {
                const i = sizes.len - reverse_i - 1;
                if (size >= pmm_size and is_aligned(pmm_size, region_address))
                {
                }
            }
        }
    }

    log("Everything worked so far!\n");
    arch.spin();
}

pub fn TODO() noreturn
{
    @panic("@TODO: Not implemented\n");
}
