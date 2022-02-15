const std = @import("std");
const kernel = @import("../src/kernel/kernel.zig");

var stivale2_term: ?stivale2_struct_tag_terminal = null;
var stivale2_framebuffer: ?stivale2_struct_tag_framebuffer = null;

fn putchar_uart(uart: stivale2_struct_tag_mmio32_uart, chr: u8) void {
    @intToPtr(*volatile u32, uart.addr).* = chr;
}

fn puts_terminal(term: stivale2_struct_tag_terminal, str: []const u8) void {
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

fn parse_tag(comptime T: type, tag: *align(1) stivale2_tag) T {
    return @ptrCast(*align(1) T, tag).*;
}

export fn _start(info: *align(1) stivale2_struct) callconv(.C) noreturn {
    { // Parse tags
        var tag_opt = @intToPtr(?*align(1) stivale2_tag, info.tags);
        while (tag_opt) |tag| {
            switch (tag.identifier) {
                STIVALE2_STRUCT_TAG_TERMINAL_ID => stivale2_term = parse_tag(stivale2_struct_tag_terminal, tag),
                STIVALE2_STRUCT_TAG_FRAMEBUFFER_ID => stivale2_framebuffer = parse_tag(stivale2_struct_tag_framebuffer, tag),

                else => {}, // Ignore unknown tags
            }
            tag_opt = @intToPtr(?*align(1) stivale2_tag, tag.next);
        }
    }

    kernel.main();
}

pub const struct_stivale2_tag = packed struct {
    identifier: u64,
    next: u64,
};
pub const struct_stivale2_header = packed struct {
    entry_point: u64,
    stack: u64,
    flags: u64,
    tags: u64,
};
pub const struct_stivale2_header_tag_framebuffer = packed struct {
    tag: struct_stivale2_tag,
    framebuffer_width: u16,
    framebuffer_height: u16,
    framebuffer_bpp: u16,
};
pub const struct_stivale2_header_tag_terminal = packed struct {
    tag: struct_stivale2_tag,
    flags: u64,
};
pub const struct_stivale2_header_tag_smp = packed struct {
    tag: struct_stivale2_tag,
    flags: u64,
};
pub const struct_stivale2_struct = packed struct {
    bootloader_brand: [64]u8,
    bootloader_version: [64]u8,
    tags: u64,
};
pub const struct_stivale2_struct_tag_cmdline = packed struct {
    tag: struct_stivale2_tag,
    cmdline: u64,
};
pub const struct_stivale2_mmap_entry = packed struct {
    base: u64,
    length: u64,
    type: u32,
    unused: u32,
};
pub const struct_stivale2_struct_tag_memmap = packed struct {
    tag: struct_stivale2_tag align(1),
    entries: u64,
    pub fn memmap(self: anytype) @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), struct_stivale2_mmap_entry) {
        const Intermediate = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
        const ReturnType = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), struct_stivale2_mmap_entry);
        return @ptrCast(ReturnType, @alignCast(@alignOf(struct_stivale2_mmap_entry), @ptrCast(Intermediate, self) + 24));
    }
};
pub const struct_stivale2_struct_tag_framebuffer = packed struct {
    tag: struct_stivale2_tag,
    framebuffer_addr: u64,
    framebuffer_width: u16,
    framebuffer_height: u16,
    framebuffer_pitch: u16,
    framebuffer_bpp: u16,
    memory_model: u8,
    red_mask_size: u8,
    red_mask_shift: u8,
    green_mask_size: u8,
    green_mask_shift: u8,
    blue_mask_size: u8,
    blue_mask_shift: u8,
};
pub const struct_stivale2_struct_tag_edid = packed struct {
    tag: struct_stivale2_tag align(1),
    edid_size: u64,
    pub fn edid_information(self: anytype) @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8) {
        const Intermediate = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
        const ReturnType = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
        return @ptrCast(ReturnType, @alignCast(@alignOf(u8), @ptrCast(Intermediate, self) + 24));
    }
};
pub const struct_stivale2_struct_tag_terminal = packed struct {
    tag: struct_stivale2_tag,
    flags: u32,
    cols: u16,
    rows: u16,
    term_write: u64,
};
pub const struct_stivale2_module = packed struct {
    begin: u64,
    end: u64,
    string: [128]u8,
};
pub const struct_stivale2_struct_tag_modules = packed struct {
    tag: struct_stivale2_tag align(1),
    module_count: u64,
    pub fn modules(self: anytype) @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), struct_stivale2_module) {
        const Intermediate = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
        const ReturnType = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), struct_stivale2_module);
        return @ptrCast(ReturnType, @alignCast(@alignOf(struct_stivale2_module), @ptrCast(Intermediate, self) + 24));
    }
};
pub const struct_stivale2_struct_tag_rsdp = packed struct {
    tag: struct_stivale2_tag,
    rsdp: u64,
};
pub const struct_stivale2_struct_tag_epoch = packed struct {
    tag: struct_stivale2_tag,
    epoch: u64,
};
pub const struct_stivale2_struct_tag_firmware = packed struct {
    tag: struct_stivale2_tag,
    flags: u64,
};
pub const struct_stivale2_struct_tag_efi_system_table = packed struct {
    tag: struct_stivale2_tag,
    system_table: u64,
};
pub const struct_stivale2_struct_tag_kernel_file = packed struct {
    tag: struct_stivale2_tag,
    kernel_file: u64,
};
pub const struct_stivale2_struct_tag_kernel_slide = packed struct {
    tag: struct_stivale2_tag,
    kernel_slide: u64,
};
pub const struct_stivale2_struct_tag_smbios = packed struct {
    tag: struct_stivale2_tag,
    flags: u64,
    smbios_entry_32: u64,
    smbios_entry_64: u64,
};
pub const struct_stivale2_smp_info = packed struct {
    processor_id: u32,
    lapic_id: u32,
    target_stack: u64,
    goto_address: u64,
    extra_argument: u64,
};
pub const struct_stivale2_struct_tag_smp = packed struct {
    tag: struct_stivale2_tag align(1),
    flags: u64,
    bsp_lapic_id: u32,
    unused: u32,
    cpu_count: u64,
    pub fn smp_info(self: anytype) @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), struct_stivale2_smp_info) {
        const Intermediate = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
        const ReturnType = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), struct_stivale2_smp_info);
        return @ptrCast(ReturnType, @alignCast(@alignOf(struct_stivale2_smp_info), @ptrCast(Intermediate, self) + 40));
    }
};
pub const struct_stivale2_struct_tag_pxe_server_info = packed struct {
    tag: struct_stivale2_tag,
    server_ip: u32,
};
pub const struct_stivale2_struct_tag_mmio32_uart = packed struct {
    tag: struct_stivale2_tag,
    addr: u64,
};
pub const struct_stivale2_struct_tag_dtb = packed struct {
    tag: struct_stivale2_tag,
    addr: u64,
    size: u64,
};
pub const struct_stivale2_struct_vmap = packed struct {
    tag: struct_stivale2_tag,
    addr: u64,
};
pub const STIVALE2_HEADER_TAG_FRAMEBUFFER_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x3ecc1bc43d0f7971, .hexadecimal);
pub const STIVALE2_HEADER_TAG_FB_MTRR_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x4c7bb07731282e00, .hexadecimal);
pub const STIVALE2_HEADER_TAG_TERMINAL_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0xa85d499b1823be72, .hexadecimal);
pub const STIVALE2_HEADER_TAG_SMP_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x1ab015085f3273df, .hexadecimal);
pub const STIVALE2_HEADER_TAG_5LV_PAGING_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x932f477032007e8f, .hexadecimal);
pub const STIVALE2_HEADER_TAG_UNMAP_NULL_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x92919432b16fe7e7, .hexadecimal);
pub const STIVALE2_BOOTLOADER_BRAND_SIZE = @as(c_int, 64);
pub const STIVALE2_BOOTLOADER_VERSION_SIZE = @as(c_int, 64);
pub const STIVALE2_STRUCT_TAG_CMDLINE_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0xe5e76a1b4597a781, .hexadecimal);
pub const STIVALE2_STRUCT_TAG_MEMMAP_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x2187f79e8612de07, .hexadecimal);
pub const STIVALE2_MMAP_USABLE = @as(c_int, 1);
pub const STIVALE2_MMAP_RESERVED = @as(c_int, 2);
pub const STIVALE2_MMAP_ACPI_RECLAIMABLE = @as(c_int, 3);
pub const STIVALE2_MMAP_ACPI_NVS = @as(c_int, 4);
pub const STIVALE2_MMAP_BAD_MEMORY = @as(c_int, 5);
pub const STIVALE2_MMAP_BOOTLOADER_RECLAIMABLE = @as(c_int, 0x1000);
pub const STIVALE2_MMAP_KERNEL_AND_MODULES = @as(c_int, 0x1001);
pub const STIVALE2_MMAP_FRAMEBUFFER = @as(c_int, 0x1002);
pub const STIVALE2_STRUCT_TAG_FRAMEBUFFER_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x506461d2950408fa, .hexadecimal);
pub const STIVALE2_FBUF_MMODEL_RGB = @as(c_int, 1);
pub const STIVALE2_STRUCT_TAG_EDID_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x968609d7af96b845, .hexadecimal);
pub const STIVALE2_STRUCT_TAG_FB_MTRR_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x6bc1a78ebe871172, .hexadecimal);
pub const STIVALE2_STRUCT_TAG_TERMINAL_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0xc2b3f4c3233b0974, .hexadecimal);
pub const STIVALE2_STRUCT_TAG_MODULES_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x4b6fe466aade04ce, .hexadecimal);
pub const STIVALE2_MODULE_STRING_SIZE = @as(c_int, 128);
pub const STIVALE2_STRUCT_TAG_RSDP_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x9e1786930a375e78, .hexadecimal);
pub const STIVALE2_STRUCT_TAG_EPOCH_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x566a7bed888e1407, .hexadecimal);
pub const STIVALE2_STRUCT_TAG_FIRMWARE_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x359d837855e3858c, .hexadecimal);
pub const STIVALE2_FIRMWARE_BIOS = @as(c_int, 1) << @as(c_int, 0);
pub const STIVALE2_STRUCT_TAG_EFI_SYSTEM_TABLE_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x4bc5ec15845b558e, .hexadecimal);
pub const STIVALE2_STRUCT_TAG_KERNEL_FILE_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0xe599d90c2975584a, .hexadecimal);
pub const STIVALE2_STRUCT_TAG_KERNEL_SLIDE_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0xee80847d01506c57, .hexadecimal);
pub const STIVALE2_STRUCT_TAG_SMBIOS_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x274bd246c62bf7d1, .hexadecimal);
pub const STIVALE2_STRUCT_TAG_SMP_ID = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x34d1d96339647025, .hexadecimal);
pub const STIVALE2_STRUCT_TAG_PXE_SERVER_INFO = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x29d1e96239247032, .hexadecimal);
pub const STIVALE2_STRUCT_TAG_MMIO32_UART = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0xb813f9b8dbc78797, .hexadecimal);
pub const STIVALE2_STRUCT_TAG_DTB = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0xabb29bd49a2833fa, .hexadecimal);
pub const STIVALE2_STRUCT_TAG_VMAP = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0xb0ed257db18cb58f, .hexadecimal);
pub const stivale2_tag = struct_stivale2_tag;
pub const stivale2_header = struct_stivale2_header;
pub const stivale2_header_tag_framebuffer = struct_stivale2_header_tag_framebuffer;
pub const stivale2_header_tag_terminal = struct_stivale2_header_tag_terminal;
pub const stivale2_header_tag_smp = struct_stivale2_header_tag_smp;
pub const stivale2_struct = struct_stivale2_struct;
pub const stivale2_struct_tag_cmdline = struct_stivale2_struct_tag_cmdline;
pub const stivale2_mmap_entry = struct_stivale2_mmap_entry;
pub const stivale2_struct_tag_memmap = struct_stivale2_struct_tag_memmap;
pub const stivale2_struct_tag_framebuffer = struct_stivale2_struct_tag_framebuffer;
pub const stivale2_struct_tag_edid = struct_stivale2_struct_tag_edid;
pub const stivale2_struct_tag_terminal = struct_stivale2_struct_tag_terminal;
pub const stivale2_module = struct_stivale2_module;
pub const stivale2_struct_tag_modules = struct_stivale2_struct_tag_modules;
pub const stivale2_struct_tag_rsdp = struct_stivale2_struct_tag_rsdp;
pub const stivale2_struct_tag_epoch = struct_stivale2_struct_tag_epoch;
pub const stivale2_struct_tag_firmware = struct_stivale2_struct_tag_firmware;
pub const stivale2_struct_tag_efi_system_table = struct_stivale2_struct_tag_efi_system_table;
pub const stivale2_struct_tag_kernel_file = struct_stivale2_struct_tag_kernel_file;
pub const stivale2_struct_tag_kernel_slide = struct_stivale2_struct_tag_kernel_slide;
pub const stivale2_struct_tag_smbios = struct_stivale2_struct_tag_smbios;
pub const stivale2_smp_info = struct_stivale2_smp_info;
pub const stivale2_struct_tag_smp = struct_stivale2_struct_tag_smp;
pub const stivale2_struct_tag_pxe_server_info = struct_stivale2_struct_tag_pxe_server_info;
pub const stivale2_struct_tag_mmio32_uart = struct_stivale2_struct_tag_mmio32_uart;
pub const stivale2_struct_tag_dtb = struct_stivale2_struct_tag_dtb;
pub const stivale2_struct_vmap = struct_stivale2_struct_vmap;
