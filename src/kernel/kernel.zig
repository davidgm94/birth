pub const arch = @import("arch/x86_64.zig");
const stivale = @import("stivale");

const std = @import("std");

pub fn log(str: []const u8) void
{
    stivale.terminal_write(str);
    arch.write_to_debug_port(str);
}

fn log_format(format_buffer: []u8, comptime format: []const u8, args: anytype) callconv(.Inline) []u8
{
    return std.fmt.bufPrint(format_buffer, format, args) catch @panic("unable to format log call");
}

var log_format_buffer: [0x4000]u8 = undefined;

pub fn logf(comptime format: []const u8, args: anytype) void
{
    const formatted_slice = log_format(&log_format_buffer, format, args);
    log(formatted_slice);
}

pub fn main() noreturn
{
    arch.set_cpu_local_storage(0);
    arch.fpu_flags();
    arch.init_interrupts();
    log("\x1b[31mHello, \x1b[33mworld!\x1b[0m\n");
    arch.spin();
}

pub fn TODO() noreturn
{
    @panic("TODO: Not implemented\n");
}
