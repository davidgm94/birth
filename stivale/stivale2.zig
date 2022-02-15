const std = @import("std");
const kernel = @import("../src/kernel/kernel.zig");
const stivale = @import("header.zig");

var terminal: stivale.Struct.Terminal = undefined;
var framebuffer: stivale.Struct.Framebuffer = undefined;

pub fn terminal_write(str: []const u8) callconv(.Inline) void
{
    const write = @intToPtr(fn ([*]const u8, usize) callconv(.C) void, terminal.term_write);
    write(str.ptr, str.len);
}

fn parse_tags(info: *align(1) stivale.Struct) void
{
    // Parse tags
    var found_terminal = false;
    defer if (!found_terminal) @panic("Stivale terminal not found\n");
    var found_framebuffer = false;
    defer if (!found_framebuffer) @panic("Stivale framebuffer not found\n");

    var tag_opt = @intToPtr(?*align(1) stivale.Tag, info.tags);

    while (tag_opt) |tag|
    {
        switch (tag.identifier)
        {
            stivale.Struct.Terminal.id =>
            {
                terminal = @ptrCast(*align(1) stivale.Struct.Terminal, tag).*;
                found_terminal = true;
            },
            stivale.Struct.Framebuffer.id =>
            {
                framebuffer = @ptrCast(*align(1) stivale.Struct.Framebuffer, tag).*;
                found_framebuffer = true;
            },
            else => {}, // Ignore unknown tags
        }

        tag_opt = @intToPtr(?*align(1) stivale.Tag, tag.next);
    }
}

export fn _start(info: *align(1) stivale.Struct) callconv(.C) noreturn
{
    parse_tags(info);
    kernel.main();
}

