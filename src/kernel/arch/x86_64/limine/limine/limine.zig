const ID = [4]u64;

fn request_id(c: u64, d: u64) ID {
    return .{ 0xc7b1dd30df4c8b88, 0x0a82e883a194f07b, c, d };
}

pub const UUID = extern struct {
    a: u32,
    b: u16,
    c: u16,
    d: [8]u8,
};

pub const File = extern struct {
    revision: u64,
    address: u64,
    size: u64,
    path: [*:0]const u8,
    command_line: [*:0]const u8,
    media_type: MediaType,
    unused: u32,
    tftp_ip: u32,
    tftp_port: u32,
    partition_index: u32,
    mbr_disk_id: u32,
    gpt_disk_uuid: UUID,
    gpt_part_uuid: UUID,
    part_uuid: UUID,

    pub const MediaType = enum(u32) {
        generic = 0,
        optical = 1,
        tftp = 2,
    };
};

pub const BootloaderInfo = extern struct {
    pub const Request = extern struct {
        id: ID = request_id(0xf55038d8e2a1202f, 0x279426fcf5f59740),
        revision: u64,
        response: ?*const Response = null,
    };

    pub const Response = extern struct {
        revision: u64,
        name: [*:0]const u8,
        version: [*:0]const u8,
    };
};

pub const StackSize = extern struct {
    pub const Request = extern struct {
        id: ID = request_id(0x224ef0460a8e8926, 0xe1cb0fc25f46ea3d),
        revision: u64,
        response: ?*const Response = null,
        stack_size: u64,
    };

    pub const Response = extern struct {
        revision: u64,
    };
};

pub const HHDM = extern struct {
    pub const Request = extern struct {
        id: ID = request_id(0x48dcf1cb8ad2b852, 0x63984e959a98244b),
        revision: u64,
        response: ?*const Response = null,
    };

    pub const Response = extern struct {
        revision: u64,
        offset: u64,
    };
};

pub const Framebuffer = extern struct {
    address: u64,
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
    edid: u64,

    pub const Request = extern struct {
        id: ID = request_id(0x9d5827dcd881dd75, 0xa3148604f6fab11b),
        revision: u64,
        response: ?*const Response = null,
    };

    pub const Response = extern struct {
        revision: u64,
        framebuffer_count: u64,
        framebuffers: ?*const [*]const Framebuffer,
    };
};

//#define LIMINE_TERMINAL_CB_DEC 10
//#define LIMINE_TERMINAL_CB_BELL 20
//#define LIMINE_TERMINAL_CB_PRIVATE_ID 30
//#define LIMINE_TERMINAL_CB_STATUS_REPORT 40
//#define LIMINE_TERMINAL_CB_POS_REPORT 50
//#define LIMINE_TERMINAL_CB_KBD_LEDS 60
//#define LIMINE_TERMINAL_CB_MODE 70
//#define LIMINE_TERMINAL_CB_LINUX 80

//#define LIMINE_TERMINAL_CTX_SIZE ((uint64_t)(-1))
//#define LIMINE_TERMINAL_CTX_SAVE ((uint64_t)(-2))
//#define LIMINE_TERMINAL_CTX_RESTORE ((uint64_t)(-3))
//#define LIMINE_TERMINAL_FULL_REFRESH ((uint64_t)(-4))

pub const Terminal = extern struct {
    columns: u64,
    rows: u64,
    framebuffer: ?*Framebuffer,

    pub const Request = extern struct {
        id: ID = request_id(0xc8ac59310c2b0844, 0xa68d0c7265d38878),
        revision: u64,
        response: ?*const Response = null,
        callback: ?*const Callback,
    };

    pub const Response = extern struct {
        revision: u64,
        terminal_count: u64,
        terminals: ?*const [*]Terminal,
        write: ?*const Write,
    };

    pub const Write = fn (*Terminal, [*:0]const u8, u64) callconv(.C) void;
    pub const Callback = fn (*Terminal, u64, u64, u64, u64) callconv(.C) void;
};

pub const Paging5Level = extern struct {
    pub const Request = extern struct {
        id: ID = request_id(0x94469551da9b3192, 0xebe5e86db7382888),
        revision: u64,
        response: ?*const Response = null,
    };

    pub const Response = extern struct {
        revision: u64,
    };
};

const SMPInfoGoToAddress = fn (*SMPInfo) callconv(.C) void;

const SMPInfoRequest = extern struct {
    id: ID = request_id(0x95a67b819a1b857e, 0xa0b61b723b6a73e0),
    revision: u64,
    response: ?*const SMPInfo.Response = null,
    flags: u64,
};

pub const SMPInfo = switch (@import("builtin").cpu.arch) {
    .x86_64 => extern struct {
        processor_id: u32,
        lapic_id: u32,
        reserved: u64,
        goto_address: ?*const SMPInfoGoToAddress,
        extra_argument: u64,

        pub const Request = SMPInfoRequest;

        pub const Response = extern struct {
            revision: u64,
            flags: u32,
            bsp_lapic_id: u32,
            cpu_count: u64,
            cpus: ?*const [*]const SMPInfo,
        };
    },
    .aarch64 => extern struct {
        processor_id: u32,
        gic_iface_no: u32,
        mpidr: u64,
        reserved: u64,
        goto_address: ?*const SMPInfoGoToAddress,
        extra_argument: u64,

        pub const Request = SMPInfoRequest;

        pub const Response = extern struct {
            revision: u64,
            flags: u32,
            bsp_mpidr: u64,
            cpu_count: u64,
            cpus: ?*const [*]const SMPInfo,
        };
    },
    else => @compileError("Architecture not supported"),
};

//define LIMINE_SMP_X2APIC (1 << 0)

// #define LIMINE_MEMMAP_USABLE                 0
// #define LIMINE_MEMMAP_RESERVED               1
// #define LIMINE_MEMMAP_ACPI_RECLAIMABLE       2
// #define LIMINE_MEMMAP_ACPI_NVS               3
// #define LIMINE_MEMMAP_BAD_MEMORY             4
// #define LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE 5
// #define LIMINE_MEMMAP_KERNEL_AND_MODULES     6
// #define LIMINE_MEMMAP_FRAMEBUFFER            7
pub const MemoryMap = extern struct {
    pub const Entry = extern struct {
        address: u64,
        length: u64,
        type: u64,
    };

    pub const Request = extern struct {
        id: ID = request_id(0x67cf3d9d378a806f, 0xe304acdfc50c3c62),
        revision: u64,
        response: ?*const Response = null,
    };

    pub const Response = extern struct {
        revision: u64,
        entry_count: u64,
        entries: ?*const [*]const Entry,
    };
};

pub const EntryPoint = extern struct {
    pub const Function = fn () callconv(.C) noreturn;

    pub const Request = extern struct {
        id: ID = request_id(0x13d86c035a1cd3e1, 0x2b0caa89d8f3026a),
        revision: u64,
        response: ?*const Response = null,
        entry_point: *const Function,
    };

    pub const Response = extern struct {
        revision: u64,
    };
};

pub const KernelFile = extern struct {
    pub const Request = extern struct {
        id: ID = request_id(0xad97e90e83f1ed67, 0x31eb5d1c5ff23b69),
        revision: u64,
        response: ?*const Response = null,
    };

    pub const Response = extern struct {
        revision: u64,
        file: ?*const File,
    };
};

pub const Module = extern struct {
    pub const Request = extern struct {
        id: ID = request_id(0x3e7e279702be32af, 0xca1c4f3bd1280cee),
        revision: u64,
        response: ?*const Response = null,
    };

    pub const Response = extern struct {
        revision: u64,
        module_count: u64,
        modules: ?*const [*]const File,
    };
};

pub const RSDP = extern struct {
    pub const Request = extern struct {
        id: ID = request_id(0xc5e77b6b397e7b43, 0x27637845accdcf3c),
        revision: u64,
        response: ?*const Response = null,
    };

    pub const Response = extern struct {
        revision: u64,
        address: u64,
    };
};

pub const SMBIOS = extern struct {
    pub const Request = extern struct {
        id: ID = request_id(0x9e9046f11e095391, 0xaa4a520fefbde5ee),
        revision: u64,
        response: ?*const Response = null,
    };

    pub const Response = extern struct {
        revision: u64,
        entry_32: u64,
        entry_64: u64,
    };
};

pub const EFISystemTable = extern struct {
    pub const Request = extern struct {
        id: ID = request_id(0x5ceba5163eaaf6d6, 0x0a6981610cf65fcc),
        revision: u64,
        response: ?*const Response = null,
    };

    pub const Response = extern struct {
        revision: u64,
        address: u64,
    };
};

pub const BootTime = extern struct {
    pub const Request = extern struct {
        id: ID = request_id(0x502746e184c088aa, 0xfbc5ec83e6327893),
        revision: u64,
        response: ?*const Response = null,
    };

    pub const Response = extern struct {
        revision: u64,
        boot_time: i64,
    };
};

pub const KernelAddress = extern struct {
    pub const Request = extern struct {
        id: ID = request_id(0x71ba76863cc55f63, 0xb2644a48c516a487),
        revision: u64,
        response: ?*const Response = null,
    };

    pub const Response = extern struct {
        revision: u64,
        physical_address: u64,
        virtual_address: u64,
    };
};

pub const DTB = extern struct {
    pub const Request = extern struct {
        id: ID = request_id(0xb40ddb48fb54bac7, 0x545081493f81ffb7),
        revision: u64,
        response: ?*const Response = null,
    };
    pub const Response = extern struct {
        revision: u64,
        address: u64,
    };
};
