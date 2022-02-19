pub const arch = @import("arch/x86_64.zig");
const stivale = @import("stivale");

const std = @import("std");

pub const LocalStorage = struct
{
    arch: arch.LocalStorage,
};

pub fn log(str: []const u8) void
{
    stivale.terminal_write(str);
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

pub fn main() noreturn
{
    log("Welcome to the RNU kernel!\n");
    arch.init();
    log("Everything worked so far!\n");
    arch.spin();
}

pub fn TODO() noreturn
{
    @panic("TODO: Not implemented\n");
}
