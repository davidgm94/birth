const std = @import("std");
const assert = std.debug.assert;
const kernel = @import("../src/kernel/kernel.zig");
const stivale = @import("header.zig");
pub const Struct = stivale.Struct;

pub fn parse_tags(info: *align(1) stivale.Struct) callconv(.C) void
{
    // Parse tags
    var found_terminal = false;
    defer if (!found_terminal) @panic("Stivale terminal not found\n");
    var found_framebuffer = false;
    defer if (!found_framebuffer) @panic("Stivale framebuffer not found\n");
    var found_rsdp = false;
    defer if (!found_rsdp) @panic("Stivale RSDP not found\n");
    var found_memory_map = false;
    defer if (!found_memory_map) @panic("Stivale memory map not found\n");

    var tag_opt = @intToPtr(?*align(1) stivale.Tag, info.tags);

    while (tag_opt) |tag|
    {
        switch (tag.identifier)
        {
            stivale.Struct.Terminal.id =>
            {
                const terminal = @ptrCast(*align(1) stivale.Struct.Terminal, tag);
                kernel.bootloader.info.terminal_callback = @intToPtr(@TypeOf(kernel.bootloader.info.terminal_callback), terminal.term_write);
                found_terminal = true;
            },
            stivale.Struct.Framebuffer.id =>
            {
                const framebuffer = @ptrCast(*align(1) stivale.Struct.Framebuffer, tag);
                _ = framebuffer;
                found_framebuffer = true;
            },
            stivale.Struct.RSDP.id =>
            {
                const rsdp = @ptrCast(*align(1) stivale.Struct.RSDP, tag);
                kernel.bootloader.info.rsdp_address = rsdp.rsdp;
                found_rsdp = true;
            },
            stivale.Struct.MemoryMap.id =>
            {
                const memory_map = @ptrCast(*align(1) stivale.Struct.MemoryMap, tag);
                const memory_map_entries = memory_map.memmap()[0..memory_map.entries];

                for (memory_map_entries) |*entry|
                {
                    kernel.logf("Memory map entry. Address: 0x{x}. Size: {}. Type: {s}\n", .{entry.base, entry.length, @tagName(entry.type)});

                    if (entry.type == .usable)
                    {
                        const index = kernel.bootloader.info.memory_map_entry_count;
                        assert(index < kernel.bootloader.info.memory_map_entries.len);
                        kernel.bootloader.info.memory_map_entries[index] = .
                        {
                            .address = entry.base,
                            .size = entry.length,
                        };
                        kernel.bootloader.info.memory_map_entry_count += 1;
                    }
                }

                found_memory_map = true;
            },
            stivale.Struct.SMP.id =>
            {
                kernel.log("@TODO: Stivale SMP tag\n");
            },
            stivale.Struct.HHDM.id =>
            {
                kernel.log("@TODO: Stivale HHDM tag\n");
            },
            stivale.Struct.EDID.id =>
            {
                kernel.log("@TODO: Stivale EDID tag\n");
            },
            stivale.Struct.Epoch.id =>
            {
                kernel.log("@TODO: Stivale Epoch tag\n");
            },
            stivale.Struct.KernelFile.id =>
            {
                kernel.log("@TODO: Stivale KernelFile tag\n");
            },
            stivale.Struct.SMBios.id =>
            {
                kernel.log("@TODO: Stivale SMBios tag\n");
            },
            stivale.Struct.Modules.id =>
            {
                kernel.log("@TODO: Stivale Modules tag\n");
            },
            stivale.Struct.Firmware.id =>
            {
                kernel.log("@TODO: Stivale Firmware tag\n");
            },
            stivale.Struct.KernelSlide.id =>
            {
                kernel.log("@TODO: Stivale KernelSlide tag\n");
            },
            stivale.Struct.KernelFileV2.id =>
            {
                kernel.log("@TODO: Stivale KernelFileV2 tag\n");
            },
            stivale.Struct.BootVolume.id =>
            {
                kernel.log("@TODO: Stivale BootVolume tag\n");
            },
            stivale.Struct.CommandLine.id =>
            {
                kernel.log("@TODO: Stivale CommandLine tag\n");
            },
            else => |tag_id|
            {
                kernel.panic("Unknown tag: 0x{x}\n", .{tag_id});
            },
        }

        tag_opt = @intToPtr(?*align(1) stivale.Tag, tag.next);
    }
}
