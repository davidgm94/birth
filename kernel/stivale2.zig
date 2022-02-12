const std = @import("std");
const kernel = @import("kernel.zig");

const stivale2 = @cImport(
    @cInclude("stivale2.h"),
);

pub const panic = kernel.panic;

var stivale2_uart: ?stivale2.stivale2_struct_tag_mmio32_uart = null;
var stivale2_term: ?stivale2.stivale2_struct_tag_terminal = null;
var stivale2_framebuffer: ?stivale2.stivale2_struct_tag_framebuffer = null;

fn putchar_uart(uart: stivale2.stivale2_struct_tag_mmio32_uart, chr: u8) void {
    @intToPtr(*volatile u32, uart.addr).* = chr;
}

fn puts_terminal(term: stivale2.stivale2_struct_tag_terminal, str: []const u8) void {
    const write = @intToPtr(fn ([*]const u8, usize) callconv(.C) void, term.term_write);
    write(str.ptr, str.len);
}

pub fn puts(str: []const u8) void {
    if (stivale2_term) |term| puts_terminal(term, str);

    for (str) |chr| {
        if (stivale2_uart) |u| putchar_uart(u, chr);

        if (comptime (@import("builtin").target.cpu.arch == .x86_64)) {
            asm volatile ("outb %[value], $0xE9"
                :
                : [value] "{al}" (chr),
            );
        }
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

                stivale2.STIVALE2_STRUCT_TAG_MMIO32_UART => stivale2_uart = parse_tag(stivale2.stivale2_struct_tag_mmio32_uart, tag),

                stivale2.STIVALE2_STRUCT_TAG_FRAMEBUFFER_ID => stivale2_framebuffer = parse_tag(stivale2.stivale2_struct_tag_framebuffer, tag),

                else => {}, // Ignore unknown tags
            }
            tag_opt = @intToPtr(?*align(1) stivale2.stivale2_tag, tag.next);
        }
    }

    kernel.kmain();
}
