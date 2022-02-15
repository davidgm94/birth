pub const Tag = packed struct
{
    identifier: u64,
    next: u64,
};

pub const Header = packed struct
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

    pub const Framebuffer = packed struct
    {
        tag: Tag,
        framebuffer_width: u16,
        framebuffer_height: u16,
        framebuffer_bpp: u16,
    };

    pub const Terminal = packed struct
    {
        tag: Tag,
        flags: u64,
    };

    pub const SMP = packed struct
    {
        tag: Tag,
        flags: u64,
    };
};

pub const Struct = packed struct
{
    bootloader_brand: [64]u8,
    bootloader_version: [64]u8,
    tags: u64,

    pub const fb_mtrr_id = 0x6bc1a78ebe871172;

    pub const CommandLineTag = packed struct
    {
        tag: Tag,
        cmdline: u64,
        pub const id = 0xe5e76a1b4597a781;
    };

    pub const MMap = packed struct
    {
        tag: Tag align(1),
        entries: u64,
        pub fn memmap(self: anytype) @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), Entry)
        {
            const Intermediate = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
            const ReturnType = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), Entry);
            return @ptrCast(ReturnType, @alignCast(@alignOf(Entry), @ptrCast(Intermediate, self) + 24));
        }

        pub const usable = 1;
        pub const reserved = 2;
        pub const acpi_reclaimable = 3;
        pub const acpi_nvs = 4;
        pub const bad_memory = 5;
        pub const bootloader_reclaimable = 0x1000;
        pub const kernel_and_modules = 0x1001;
        pub const framebuffer = 0x1002;
        
        pub const Entry = packed struct
        {
            base: u64,
            length: u64,
            type: u32,
            unused: u32,
        };
        pub const id = 0x2187f79e8612de07;
    };

    pub const Framebuffer = packed struct
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

        pub const memory_model_rgb = 1;
        pub const id = 0x506461d2950408fa;
    };

    pub const EDID = packed struct
    {
        tag: Tag align(1),
        edid_size: u64,
        pub fn edid_information(self: anytype) @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8) {
            const Intermediate = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
            const ReturnType = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
            return @ptrCast(ReturnType, @alignCast(@alignOf(u8), @ptrCast(Intermediate, self) + 24));
        }
        pub const id = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x968609d7af96b845, .hexadecimal);
    };

    pub const Terminal = packed struct
    {
        tag: Tag,
        flags: u32,
        cols: u16,
        rows: u16,
        term_write: u64,

        pub const id = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0xc2b3f4c3233b0974, .hexadecimal);
    };

    pub const Modules = packed struct
    {
        tag: Tag align(1),
        module_count: u64,
        pub fn modules(self: anytype) @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), Module) {
            const Intermediate = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
            const ReturnType = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), Module);
            return @ptrCast(ReturnType, @alignCast(@alignOf(Module), @ptrCast(Intermediate, self) + 24));
        }

        pub const Module = packed struct
        {
            begin: u64,
            end: u64,
            string: [128]u8,
        };

        pub const id = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x4b6fe466aade04ce, .hexadecimal);
    };

    pub const RSDP = packed struct
    {
        tag: Tag,
        rsdp: u64,

        pub const id = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x9e1786930a375e78, .hexadecimal);
    };

    pub const Epoch = packed struct
    {
        tag: Tag,
        epoch: u64,

        pub const id = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x566a7bed888e1407, .hexadecimal);
    };

    pub const Firmware = packed struct
    {
        tag: Tag,
        flags: u64,

        pub const bios = 1 << 0;

        pub const id = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x359d837855e3858c, .hexadecimal);
    };

    pub const EFISystemTable = packed struct
    {
        tag: Tag,
        system_table: u64,

        pub const id = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x4bc5ec15845b558e, .hexadecimal);
    };

    pub const KernelFile = packed struct
    {
        tag: Tag,
        kernel_file: u64,

        pub const id = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0xe599d90c2975584a, .hexadecimal);
    };

    pub const KernelSlide = packed struct
    {
        tag: Tag,
        kernel_slide: u64,

        pub const id = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0xee80847d01506c57, .hexadecimal);
    };

    pub const SMBios = packed struct
    {
        tag: Tag,
        flags: u64,
        smbios_entry_32: u64,
        smbios_entry_64: u64,

        pub const id = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x274bd246c62bf7d1, .hexadecimal);
    };

    pub const SMP = packed struct
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

        pub const Info = packed struct
        {
            processor_id: u32,
            lapic_id: u32,
            target_stack: u64,
            goto_address: u64,
            extra_argument: u64,
        };

        pub const id = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x34d1d96339647025, .hexadecimal);
    };

    pub const PXEServerInfo = packed struct
    {
        tag: Tag,
        server_ip: u32,

        pub const id = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0x29d1e96239247032, .hexadecimal);
    };

    pub const MMIO32UART = packed struct
    {
        tag: Tag,
        addr: u64,

        pub const id = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0xb813f9b8dbc78797, .hexadecimal);
    };

    pub const DTB = packed struct
    {
        tag: Tag,
        addr: u64,
        size: u64,

        pub const id = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0xabb29bd49a2833fa, .hexadecimal);
    };

    pub const VMap = packed struct
    {
        tag: Tag,
        addr: u64,

        pub const id = @import("std").zig.c_translation.promoteIntLiteral(c_int, 0xb0ed257db18cb58f, .hexadecimal);
    };
};

pub const bootloader_brand_size = 64;
pub const bootloader_version_size = 64;
