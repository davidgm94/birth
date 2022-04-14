pub const builtin = @import("builtin");
pub const arch = switch (builtin.target.cpu.arch) {
    .riscv64 => @import("arch/riscv64.zig"),
    .x86_64 => @import("arch/x86_64.zig"),
    else => unreachable,
};
pub const bootloader = @import("bootloader.zig");

const std = @import("std");

pub const LocalStorage = struct {
    arch: arch.LocalStorage,
};

pub fn log(str: []const u8) void {
    if (@ptrToInt(bootloader.info.terminal_callback) != 0) {
        bootloader.info.terminal_callback(str.ptr, str.len);
    }
    arch.write_to_debug_port(str);
}

inline fn log_format(format_buffer: []u8, comptime format: []const u8, args: anytype) []u8 {
    return std.fmt.bufPrint(format_buffer, format, args) catch @panic("unable to format log call");
}

var log_format_buffer: [0x4000]u8 align(0x1000) = undefined;
pub fn logf(comptime format: []const u8, args: anytype) void {
    const formatted_slice = log_format(&log_format_buffer, format, args);
    log(formatted_slice);
}

// @TODO: turn off interrupts
var panic_format_buffer: [0x4000]u8 align(0x1000) = undefined;
pub fn panic(comptime format: []const u8, args: anytype) noreturn {
    const formatted_slice = log_format(&panic_format_buffer, format, args);
    log(formatted_slice);
    arch.spin();
}

pub fn assert(condition: bool, src: std.builtin.SourceLocation) void {
    if (!condition) panic("Assert failed at {s}:{}:{} {s}()\n", .{ src.file, src.line, src.column, src.fn_name });
}

pub const MemoryRegion = struct {
    address: u64,
    size: u64,
};

export fn _start(info: *align(1) stivale.Struct) callconv(.C) noreturn {
    stivale.parse_tags(info);
    main();
}

pub const PhysicalAllocator = struct {
    pub const sizes = [_]u64{
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

    pub const reverse_sizes = blk: {
        var result = sizes;
        std.mem.reverse(u64, &result);
        break :blk result;
    };

    var free_roots: [sizes.len]u64 = undefined;

    pub fn allocate(index: u64) error{out_of_memory}!u64 {
        if (free_roots[index] == 0) {
            if (index + 1 >= sizes.len) return error.out_of_memory;

            var next = try allocate(index + 1);
            var next_size = sizes[index + 1];
            const current_size = sizes[index];

            while (next_size > current_size) {
                free(next, index);
                next += current_size;
                next_size -= current_size;
            }

            return next;
        } else {
            const result = free_roots[index];
            const new_root = @intToPtr(*u64, (arch.PhysicalAddress{ .value = result }).get_writeback_virtual_address()).*;
            // @TODO: @Safety check
            free_roots[index] = new_root;
            return result;
        }
    }

    pub fn free(physical_address: u64, index: u64) void {
        const last = free_roots[index];
        free_roots[index] = physical_address;
        @intToPtr(*u64, (arch.PhysicalAddress{ .value = physical_address }).get_writeback_virtual_address()).* = last;
    }

    pub fn allocate_physical(size: u64) !arch.PhysicalAddress {
        for (sizes) |pmm_size, i| {
            if (size <= pmm_size) {
                // @Lock defer @Unlock
                return arch.PhysicalAddress{allocate(i)};
            }
        }

        return error.physical_allocation_too_small;
    }
};

pub fn is_aligned(value: u64, alignment: u64) bool {
    const mask = alignment - 1;
    return (value & mask) == 0;
}

pub fn align_forward(value: u64, alignment: u64) u64 {
    const mask = alignment - 1;
    return (value + mask) & ~mask;
}

fn main() noreturn {
    log("Welcome to the RNU kernel!\n");
    arch.init();

    log("Everything worked so far!\n");
    arch.spin();
}

pub fn TODO() noreturn {
    @panic("@TODO: Not implemented\n");
}
