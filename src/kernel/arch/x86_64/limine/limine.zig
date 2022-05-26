pub const limine_uuid = extern struct {
    a: u32,
    b: u16,
    c: u16,
    d: [8]u8,
};

pub const limine_file = extern struct {
    revision: u64,
    address: ?*anyopaque,
    size: u64,
    path: [*c]u8,
    cmdline: [*c]u8,
    media_type: u32,
    unused: u32,
    tftp_ip: u32,
    tftp_port: u32,
    partition_index: u32,
    mbr_disk_id: u32,
    gpt_disk_uuid: limine_uuid,
    gpt_part_uuid: limine_uuid,
    part_uuid: limine_uuid,
};

pub const limine_bootloader_info_response = extern struct {
    revision: u64,
    name: [*c]u8,
    version: [*c]u8,
};

pub const limine_bootloader_info_request = extern struct {
    id: [4]u64,
    revision: u64,
    response: [*c]limine_bootloader_info_response,
};

pub const limine_stack_size_response = extern struct {
    revision: u64,
};

pub const limine_stack_size_request = extern struct {
    id: [4]u64,
    revision: u64,
    response: [*c]limine_stack_size_response,
    stack_size: u64,
};

pub const limine_hhdm_response = extern struct {
    revision: u64,
    offset: u64,
};

pub const limine_hhdm_request = extern struct {
    id: [4]u64,
    revision: u64,
    response: [*c]limine_hhdm_response,
};

pub const limine_framebuffer = extern struct {
    address: ?*anyopaque,
    width: u64,
    height: u64,
    pitch: u64,
    bpp: u16,
    memory_model: u8,
    red_mask_size: u8,
    red_mask_shift: u8,
    green_mask_size: u8,
    green_mask_shift: u8,
    blue_mask_size: u8,
    blue_mask_shift: u8,
    unused: [7]u8,
    edid_size: u64,
    edid: ?*anyopaque,
};

pub const limine_framebuffer_response = extern struct {
    revision: u64,
    framebuffer_count: u64,
    framebuffers: [*c][*c]limine_framebuffer,
};

pub const limine_framebuffer_request = extern struct {
    id: [4]u64,
    revision: u64,
    response: [*c]limine_framebuffer_response,
};

pub const limine_framebuffer_legacy = extern struct {
    address: ?*anyopaque,
    width: u16,
    height: u16,
    pitch: u16,
    bpp: u16,
    memory_model: u8,
    red_mask_size: u8,
    red_mask_shift: u8,
    green_mask_size: u8,
    green_mask_shift: u8,
    blue_mask_size: u8,
    blue_mask_shift: u8,
    unused: u8,
    edid_size: u64,
    edid: ?*anyopaque,
};

pub const limine_framebuffer_legacy_response = extern struct {
    revision: u64,
    framebuffer_count: u64,
    framebuffers: [*c][*c]limine_framebuffer_legacy,
};

pub const limine_framebuffer_legacy_request = extern struct {
    id: [4]u64,
    revision: u64,
    response: [*c]limine_framebuffer_legacy_response,
};

pub const limine_terminal = extern struct {
    columns: u64,
    rows: u64,
    framebuffer: [*c]limine_framebuffer,
};

pub const limine_terminal_write = ?fn ([*c]limine_terminal, [*c]const u8, u64) callconv(.C) void;
pub const limine_terminal_callback = ?fn ([*c]limine_terminal, u64, u64, u64, u64) callconv(.C) void;
pub const limine_terminal_response = extern struct {
    revision: u64,
    terminal_count: u64,
    terminals: [*c][*c]limine_terminal,
    write: limine_terminal_write,
};

pub const limine_terminal_request = extern struct {
    id: [4]u64,
    revision: u64,
    response: [*c]limine_terminal_response,
    callback: limine_terminal_callback,
};

pub const limine_terminal_legacy = extern struct {
    columns: u32,
    rows: u32,
    framebuffer: [*c]limine_framebuffer_legacy,
};

pub const limine_terminal_legacy_write = ?fn ([*c]limine_terminal_legacy, [*c]const u8, u64) callconv(.C) void;
pub const limine_terminal_legacy_callback = ?fn ([*c]limine_terminal_legacy, u64, u64, u64, u64) callconv(.C) void;
pub const limine_terminal_legacy_response = extern struct {
    revision: u64,
    terminal_count: u64,
    terminals: [*c][*c]limine_terminal_legacy,
    write: limine_terminal_legacy_write,
};

pub const limine_terminal_legacy_request = extern struct {
    id: [4]u64,
    revision: u64,
    response: [*c]limine_terminal_legacy_response,
    callback: limine_terminal_legacy_callback,
};

pub const limine_5_level_paging_response = extern struct {
    revision: u64,
};

pub const limine_5_level_paging_request = extern struct {
    id: [4]u64,
    revision: u64,
    response: [*c]limine_5_level_paging_response,
};

pub const limine_goto_address = ?fn ([*c]limine_smp_info) callconv(.C) void;
pub const limine_smp_info = extern struct {
    processor_id: u32,
    lapic_id: u32,
    reserved: u64,
    goto_address: limine_goto_address,
    extra_argument: u64,
};

pub const limine_smp_response = extern struct {
    revision: u64,
    flags: u32,
    bsp_lapic_id: u32,
    cpu_count: u64,
    cpus: [*c][*c]limine_smp_info,
};

pub const limine_smp_request = extern struct {
    id: [4]u64,
    revision: u64,
    response: [*c]limine_smp_response,
    flags: u64,
};

pub const limine_memmap_entry = extern struct {
    base: u64,
    length: u64,
    type: u64,
};

pub const limine_memmap_response = extern struct {
    revision: u64,
    entry_count: u64,
    entries: [*c][*c]limine_memmap_entry,
};

pub const limine_memmap_request = extern struct {
    id: [4]u64,
    revision: u64,
    response: [*c]limine_memmap_response,
};

pub const limine_entry_point = ?fn () callconv(.C) void;
pub const limine_entry_point_response = extern struct {
    revision: u64,
};

pub const limine_entry_point_request = extern struct {
    id: [4]u64,
    revision: u64,
    response: [*c]limine_entry_point_response,
    entry: limine_entry_point,
};

pub const limine_kernel_file_response = extern struct {
    revision: u64,
    kernel_file: [*c]limine_file,
};

pub const limine_kernel_file_request = extern struct {
    id: [4]u64,
    revision: u64,
    response: [*c]limine_kernel_file_response,
};

pub const limine_module_response = extern struct {
    revision: u64,
    module_count: u64,
    modules: [*c][*c]limine_file,
};

pub const limine_module_request = extern struct {
    id: [4]u64,
    revision: u64,
    response: [*c]limine_module_response,
};

pub const limine_rsdp_response = extern struct {
    revision: u64,
    address: ?*anyopaque,
};

pub const limine_rsdp_request = extern struct {
    id: [4]u64,
    revision: u64,
    response: [*c]limine_rsdp_response,
};

pub const limine_smbios_response = extern struct {
    revision: u64,
    entry_32: ?*anyopaque,
    entry_64: ?*anyopaque,
};

pub const limine_smbios_request = extern struct {
    id: [4]u64,
    revision: u64,
    response: [*c]limine_smbios_response,
};

pub const limine_efi_system_table_response = extern struct {
    revision: u64,
    address: ?*anyopaque,
};

pub const limine_efi_system_table_request = extern struct {
    id: [4]u64,
    revision: u64,
    response: [*c]limine_efi_system_table_response,
};

pub const limine_boot_time_response = extern struct {
    revision: u64,
    boot_time: i64,
};

pub const limine_boot_time_request = extern struct {
    id: [4]u64,
    revision: u64,
    response: [*c]limine_boot_time_response,
};

pub const limine_kernel_address_response = extern struct {
    revision: u64,
    physical_base: u64,
    virtual_base: u64,
};

pub const limine_kernel_address_request = extern struct {
    id: [4]u64,
    revision: u64,
    response: [*c]limine_kernel_address_response,
};

pub inline fn LIMINE_PTR(TYPE: anytype) @TypeOf(TYPE) {
    return TYPE;
}

pub const limine_terminal_request_id = [_]u64{ 0xc7b1dd30df4c8b88, 0x0a82e883a194f07b, 0xc8ac59310c2b0844, 0xa68d0c7265d38878 };

pub const LIMINE_MEDIA_TYPE_GENERIC = @as(c_int, 0);
pub const LIMINE_MEDIA_TYPE_OPTICAL = @as(c_int, 1);
pub const LIMINE_MEDIA_TYPE_TFTP = @as(c_int, 2);
pub const LIMINE_FRAMEBUFFER_RGB = @as(c_int, 1);
pub const LIMINE_TERMINAL_CB_DEC = @as(c_int, 10);
pub const LIMINE_TERMINAL_CB_BELL = @as(c_int, 20);
pub const LIMINE_TERMINAL_CB_PRIVATE_ID = @as(c_int, 30);
pub const LIMINE_TERMINAL_CB_STATUS_REPORT = @as(c_int, 40);
pub const LIMINE_TERMINAL_CB_POS_REPORT = @as(c_int, 50);
pub const LIMINE_TERMINAL_CB_KBD_LEDS = @as(c_int, 60);
pub const LIMINE_TERMINAL_CB_MODE = @as(c_int, 70);
pub const LIMINE_TERMINAL_CB_LINUX = @as(c_int, 80);
pub const LIMINE_TERMINAL_CTX_SIZE = @import("std").zig.c_translation.cast(u64, -@as(c_int, 1));
pub const LIMINE_TERMINAL_CTX_SAVE = @import("std").zig.c_translation.cast(u64, -@as(c_int, 2));
pub const LIMINE_TERMINAL_CTX_RESTORE = @import("std").zig.c_translation.cast(u64, -@as(c_int, 3));
pub const LIMINE_TERMINAL_FULL_REFRESH = @import("std").zig.c_translation.cast(u64, -@as(c_int, 4));
pub const LIMINE_SMP_X2APIC = @as(c_int, 1) << @as(c_int, 0);
pub const LIMINE_MEMMAP_USABLE = @as(c_int, 0);
pub const LIMINE_MEMMAP_RESERVED = @as(c_int, 1);
pub const LIMINE_MEMMAP_ACPI_RECLAIMABLE = @as(c_int, 2);
pub const LIMINE_MEMMAP_ACPI_NVS = @as(c_int, 3);
pub const LIMINE_MEMMAP_BAD_MEMORY = @as(c_int, 4);
pub const LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE = @as(c_int, 5);
pub const LIMINE_MEMMAP_KERNEL_AND_MODULES = @as(c_int, 6);
pub const LIMINE_MEMMAP_FRAMEBUFFER = @as(c_int, 7);
