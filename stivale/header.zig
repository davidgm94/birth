const std = @import("std");
const u64_max = 0xffff_ffff_ffff_ffff;

pub const Tag = extern struct
{
    identifier: u64,
    next: u64,
};

pub const Header = extern struct
{
    entry_point: u64,
    stack: u64,
    flags: u64,
    tags: u64,

    pub const framebuffer_id = 0x3ecc1bc43d0f7971;
    pub const fb_mtrr_id = 0x4c7bb07731282e00;
    pub const terminal_id = 0xa85d499b1823be72;
    pub const smp_id = 0x1ab015085f3273df;
    pub const @"5lv_paging_id" = 0x932f477032007e8f;
    pub const unmap_null_id = 0x92919432b16fe7e7;
    pub const any_video_id = 0xc75c9fa92a44c4db;
    pub const hhdmslide_id = 0xdc29269c2af53d1d;

    pub const Framebuffer = extern struct
    {
        tag: Tag,
        framebuffer_width: u16,
        framebuffer_height: u16,
        framebuffer_bpp: u16,
        _unused: u16,
    };

    pub const Terminal = extern struct
    {
        tag: Tag,
        flags: u64,
        callback: u64,

        pub const dec = 10;
        pub const bell = 10;
        pub const private_id = 30;
        pub const status_report = 40;
        pub const position_report = 50;
        pub const keyboard_leds = 60;
        pub const mode = 70;
        pub const linux = 80;

        pub const context_size: u64 = u64_max;
        pub const context_save: u64 = u64_max - 1;
        pub const context_restore: u64 = u64_max - 2;
        pub const full_refresh: u64 = u64_max - 3;
    };

    pub const SMP = extern struct
    {
        tag: Tag,
        flags: u64,
    };

    pub const AnyVideo = extern struct
    {
        tag: Tag,
        preference: u64,
    };

    pub const HHDMSlide = extern struct
    {
        tag: Tag,
        flags: u64,
        alignment: u64,
    };
};

pub const Struct = extern struct
{
    bootloader_brand: [64]u8,
    bootloader_version: [64]u8,
    tags: u64,

    pub const fb_mtrr_id = 0x6bc1a78ebe871172;

    pub const CommandLine = extern struct
    {
        tag: Tag,
        cmdline: u64,
        pub const id = 0xe5e76a1b4597a781;
    };

    pub const MemoryMap = extern struct
    {
        tag: Tag align(1),
        entries: u64,
        pub fn memmap(self: anytype) @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), Entry)
        {
            const Intermediate = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
            const ReturnType = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), Entry);
            return @ptrCast(ReturnType, @alignCast(@alignOf(Entry), @ptrCast(Intermediate, self) + 24));
        }

        pub const Entry = extern struct
        {
            base: u64,
            length: u64,
            type: Type,
            unused: u32,

            pub const Type = enum(u32)
            {
                usable = 1,
                reserved = 2,
                acpi_reclaimable = 3,
                acpi_nvs = 4,
                bad_memory = 5,
                bootloader_reclaimable = 0x1000,
                kernel_and_modules = 0x1001,
                framebuffer = 0x1002,
            };
        };
        pub const id = 0x2187f79e8612de07;
    };

    pub const Framebuffer = extern struct
    {
        tag: Tag,
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
        _unused: u8,

        pub const memory_model_rgb = 1;
        pub const id = 0x506461d2950408fa;
    };

    pub const EDID = extern struct
    {
        tag: Tag align(1),
        edid_size: u64,
        pub fn edid_information(self: anytype) @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8) {
            const Intermediate = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
            const ReturnType = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
            return @ptrCast(ReturnType, @alignCast(@alignOf(u8), @ptrCast(Intermediate, self) + 24));
        }
        pub const id = 0x968609d7af96b845;
    };

    pub const Terminal = extern struct
    {
        tag: Tag,
        flags: u32,
        cols: u16,
        rows: u16,
        term_write: u64,
        max_length: u64,

        pub const id = 0xc2b3f4c3233b0974;
    };

    pub const Modules = extern struct
    {
        tag: Tag align(1),
        module_count: u64,
        pub fn modules(self: anytype) @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), Module) {
            const Intermediate = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
            const ReturnType = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), Module);
            return @ptrCast(ReturnType, @alignCast(@alignOf(Module), @ptrCast(Intermediate, self) + 24));
        }

        pub const Module = extern struct
        {
            begin: u64,
            end: u64,
            string: [128]u8,
        };

        pub const id = 0x4b6fe466aade04ce;
    };

    pub const RSDP = extern struct
    {
        tag: Tag,
        rsdp: u64,

        pub const id = 0x9e1786930a375e78;
    };

    pub const Epoch = extern struct
    {
        tag: Tag,
        epoch: u64,

        pub const id = 0x566a7bed888e1407;
    };

    pub const Firmware = extern struct
    {
        tag: Tag,
        flags: u64,

        pub const bios = 1 << 0;

        pub const id = 0x359d837855e3858c;
    };

    pub const EFISystemTable = extern struct
    {
        tag: Tag,
        system_table: u64,

        pub const id = 0x4bc5ec15845b558e;
    };

    pub const KernelFile = extern struct
    {
        tag: Tag,
        kernel_file: u64,

        pub const id = 0xe599d90c2975584a;
    };

    pub const KernelFileV2 = extern struct
    {
        tag: Tag,
        kernel_file: u64,
        kernel_size: u64,

        pub const id = 0x37c13018a02c6ea2;
    };

    pub const KernelSlide = extern struct
    {
        tag: Tag,
        kernel_slide: u64,

        pub const id = 0xee80847d01506c57;
    };

    pub const KernelBaseAddress = extern struct
    {
        tag: Tag,
        physical_base_address: u64,
        virtual_base_address: u64,

        const id = 0x060d78874a2a8af0;
    };

    pub const SMBios = extern struct
    {
        tag: Tag,
        flags: u64,
        smbios_entry_32: u64,
        smbios_entry_64: u64,

        pub const id = 0x274bd246c62bf7d1;
    };

    pub const SMP = extern struct
    {
        tag: Tag align(1),
        flags: u64,
        bsp_lapic_id: u32,
        unused: u32,
        cpu_count: u64,
        pub fn smp_info(self: anytype) @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), Info) {
            const Intermediate = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
            const ReturnType = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), Info);
            return @ptrCast(ReturnType, @alignCast(@alignOf(Info), @ptrCast(Intermediate, self) + 40));
        }

        pub const Info = extern struct
        {
            processor_id: u32,
            lapic_id: u32,
            target_stack: u64,
            goto_address: u64,
            extra_argument: u64,
        };

        pub const id = 0x34d1d96339647025;
    };

    pub const PXEServerInfo = extern struct
    {
        tag: Tag,
        server_ip: u32,

        pub const id = 0x29d1e96239247032;
    };

    pub const MMIO32UART = extern struct
    {
        tag: Tag,
        addr: u64,

        pub const id = 0xb813f9b8dbc78797;
    };

    pub const DTB = extern struct
    {
        tag: Tag,
        addr: u64,
        size: u64,

        pub const id = 0xabb29bd49a2833fa;
    };

    pub const HHDM = extern struct
    {
        tag: Tag,
        addr: u64,

        pub const id = 0xb0ed257db18cb58f;
    };

    pub const TextMode = extern struct
    {
        tag: Tag,
        address: u64,
        unused: u16,
        rows: u16,
        columns: u16,
        bytes_per_char: u16,

        const id = 0x38d74c23e0dca893;
    };

    pub const PMRs = extern struct
    {
        tag: Tag,
        entry_count: u64,
        pub fn pmrs(self: anytype) @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), PMR)
        {
            const Intermediate = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
            const ReturnType = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), PMR);
            return @ptrCast(ReturnType, @alignCast(@alignOf(PMR), @ptrCast(Intermediate, self) + 24));
        }

        const PMR = extern struct
        {
            base: u64,
            length: u64,
            permissions: u64,

            const executable = 1 << 0;
            const writable = 1 << 1;
            const readable = 1 << 2;
        };

        const id = 0x5df266a64047b6bd;
    };

    pub const BootVolume = extern struct
    {
        tag: Tag,
        flags: u64,
        guid: GUID,
        partition_guid: GUID,

        pub const id = 0x9b4358364c19ee62;
    };
};

pub const GUID = extern struct
{
    a: u32,
    b: u16,
    c: u16,
    d: [8]u8,
};

pub const Anchor = extern struct
{
    anchor: [15]u8,
    bits: u8,
    physical_load_address: u64,
    physical_bss_start: u64,
    physical_bss_end: u64,
    physical_stivale2_header: u64,
};

pub const bootloader_brand_size = 64;
pub const bootloader_version_size = 64;
