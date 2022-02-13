const std = @import("std");
const kernel = @import("kernel.zig");

const stivale2 = @cImport(@cInclude("stivale2.h"));

var stivale2_term: ?stivale2.stivale2_struct_tag_terminal = null;
var stivale2_framebuffer: ?stivale2.stivale2_struct_tag_framebuffer = null;

fn putchar_uart(uart: stivale2.stivale2_struct_tag_mmio32_uart, chr: u8) void {
    @intToPtr(*volatile u32, uart.addr).* = chr;
}

fn puts_terminal(term: stivale2.stivale2_struct_tag_terminal, str: []const u8) void {
    const write = @intToPtr(fn ([*]const u8, usize) callconv(.C) void, term.term_write);
    write(str.ptr, str.len);
}

pub fn terminal_write(str: []const u8) callconv(.Inline) void
{
    if (stivale2_term) |term|
    {
        const write = @intToPtr(fn ([*]const u8, usize) callconv(.C) void, term.term_write);
        write(str.ptr, str.len);
    }
}

fn parse_tag(comptime T: type, tag: *align(1) stivale2.stivale2_tag) T {
    return @ptrCast(*align(1) T, tag).*;
}

export fn _start(info: *align(1) stivale2.stivale2_struct) callconv(.C) noreturn {
    { // Parse tags
        var tag_opt = @intToPtr(?*align(1) stivale2.stivale2_tag, info.tags);
        while (tag_opt) |tag| {
            switch (tag.identifier) {
                stivale2.STIVALE2_STRUCT_TAG_TERMINAL_ID => stivale2_term = parse_tag(stivale2.stivale2_struct_tag_terminal, tag),
                stivale2.STIVALE2_STRUCT_TAG_FRAMEBUFFER_ID => stivale2_framebuffer = parse_tag(stivale2.stivale2_struct_tag_framebuffer, tag),

                else => {}, // Ignore unknown tags
            }
            tag_opt = @intToPtr(?*align(1) stivale2.stivale2_tag, tag.next);
        }
    }

    kernel.main();
}
