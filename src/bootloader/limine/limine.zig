const ID = [4]u64;

fn requestID(c: u64, d: u64) ID {
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
        id: ID = requestID(0xf55038d8e2a1202f, 0x279426fcf5f59740),
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
        id: ID = requestID(0x224ef0460a8e8926, 0xe1cb0fc25f46ea3d),
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
        id: ID = requestID(0x48dcf1cb8ad2b852, 0x63984e959a98244b),
        revision: u64,
        response: ?*const Response = null,
    };

    pub const Response = extern struct {
        revision: u64,
        offset: u64,
    };
};

pub const VideoMode = extern struct {
    pitch: u64,
    width: u64,
    height: u64,
    bpp: u16,
    memory_model: u8,
    red_mask_size: u8,
    red_mask_shift: u8,
    green_mask_size: u8,
    green_mask_shift: u8,
    blue_mask_size: u8,
    blue_mask_shift: u8,
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
    mode_count: u64,
    modes: [*]const *const VideoMode,

    pub const Request = extern struct {
        id: ID = requestID(0x9d5827dcd881dd75, 0xa3148604f6fab11b),
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
        id: ID = requestID(0xc8ac59310c2b0844, 0xa68d0c7265d38878),
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
        id: ID = requestID(0x94469551da9b3192, 0xebe5e86db7382888),
        revision: u64,
        response: ?*const Response = null,
    };

    pub const Response = extern struct {
        revision: u64,
    };
};

const SMPInfoGoToAddress = fn (*SMPInfo) callconv(.C) noreturn;

pub const SMPInfoRequest = extern struct {
    id: ID = requestID(0x95a67b819a1b857e, 0xa0b61b723b6a73e0),
    revision: u64,
    response: ?*const SMPInfo.Response = null,
    flags: packed struct(u64) {
        x2apic: bool,
        reserved: u63 = 0,
    },
};

pub const SMPInfo = switch (@import("builtin").cpu.arch) {
    .x86_64 => extern struct {
        processor_id: u32,
        lapic_id: u32,
        reserved: u64,
        goto_address: ?*const SMPInfoGoToAddress,
        extra_argument: u64,

        pub const Response = extern struct {
            revision: u64,
            flags: u32,
            bsp_lapic_id: u32,
            cpu_count: u64,
            cpus: ?*const [*]SMPInfo,
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

pub const MemoryMap = extern struct {
    pub const Entry = extern struct {
        region: privileged.arch.PhysicalMemoryRegion(.global),
        type: Type,

        const Type = enum(u64) {
            usable = 0,
            reserved = 1,
            acpi_reclaimable = 2,
            acpi_nvs = 3,
            bad_memory = 4,
            bootloader_reclaimable = 5,
            kernel_and_modules = 6,
            framebuffer = 7,
        };
    };

    pub const Request = extern struct {
        id: ID = requestID(0x67cf3d9d378a806f, 0xe304acdfc50c3c62),
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
        id: ID = requestID(0x13d86c035a1cd3e1, 0x2b0caa89d8f3026a),
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
        id: ID = requestID(0xad97e90e83f1ed67, 0x31eb5d1c5ff23b69),
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
        id: ID = requestID(0x3e7e279702be32af, 0xca1c4f3bd1280cee),
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
        id: ID = requestID(0xc5e77b6b397e7b43, 0x27637845accdcf3c),
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
        id: ID = requestID(0x9e9046f11e095391, 0xaa4a520fefbde5ee),
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
        id: ID = requestID(0x5ceba5163eaaf6d6, 0x0a6981610cf65fcc),
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
        id: ID = requestID(0x502746e184c088aa, 0xfbc5ec83e6327893),
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
        id: ID = requestID(0x71ba76863cc55f63, 0xb2644a48c516a487),
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
        id: ID = requestID(0xb40ddb48fb54bac7, 0x545081493f81ffb7),
        revision: u64,
        response: ?*const Response = null,
    };
    pub const Response = extern struct {
        revision: u64,
        address: u64,
    };
};

const lib = @import("../../lib.zig");
const assert = lib.assert;
const log = lib.log.scoped(.LIMINE);

const bootloader = @import("../../bootloader.zig");

const privileged = @import("../../privileged.zig");
const stopCPU = privileged.arch.stopCPU;

pub fn limineEntryPoint() callconv(.C) noreturn {
    log.debug("Hello from Limine {s}!", .{limine_information.response.?.version});
    assert(limine_stack_size.response != null);
    log.debug("CPU count: {}", .{limine_smp.response.?.cpu_count});
    const memory_map = limine_memory_map.response.?;
    log.debug("Memory map entry count: {}", .{memory_map.entry_count});
    const memory_map_entries = memory_map.entries.?.*[0..memory_map.entry_count];
    for (memory_map_entries) |entry| {
        log.debug("Entry: 0x{x}. 0x{x}. {s}", .{ entry.region.address, entry.region.size, @tagName(entry.type) });
    }

    var merging_entries_left: usize = 0;
    var total_merge_count: usize = 0;

    var maybe_unmergeable_usable_region: ?usize = null;
    for (memory_map_entries) |entry, entry_index| {
        if (merging_entries_left > 0) {
            merging_entries_left -= 1;
            continue;
        }

        if (entry.type == .usable or entry.type == .bootloader_reclaimable) {
            log.debug("Index: {}", .{entry_index});
            if (entry_index + 1 < memory_map_entries.len) {
                var index = entry_index;
                while (index + 1 < memory_map_entries.len) : (index += 1) {
                    const mergeable_entry = memory_map_entries[index];
                    const is_mergeable = mergeable_entry.type == .usable or mergeable_entry.type == .bootloader_reclaimable;
                    if (!is_mergeable) break;
                }

                const merge_count = index - entry_index - 1;
                total_merge_count += merge_count;
                if (merge_count > 0) {
                    merging_entries_left = merge_count;

                    const size_guess = @sizeOf(bootloader.Information) + 15 * lib.arch.valid_page_sizes[0];
                    if (entry.type == .usable and entry.region.size > size_guess) {
                        maybe_unmergeable_usable_region = entry_index;
                    }
                }
                log.debug("Merge count: {}", .{merge_count});
            }
        }
    }

    const unmergeable_usable_region = maybe_unmergeable_usable_region orelse @panic("TODO: Unable to find unmergeable_usable_region");
    log.debug("unmergeable_region: {}", .{unmergeable_usable_region});

    log.debug("Total merge count: {}", .{total_merge_count});

    // Discard regions that are not useful to the CPU driver
    var discarded_region_count: usize = 0;
    for (memory_map_entries) |entry| {
        discarded_region_count += @boolToInt(entry.type == .framebuffer or entry.type == .kernel_and_modules);
    }

    const actual_memory_map_entry_count = @intCast(u32, memory_map_entries.len - discarded_region_count - total_merge_count);
    const stack_size = privileged.default_stack_size;

    const cpu_count = @intCast(u32, limine_smp.response.?.cpu_count);

    log.debug("Total discarded region count: {}", .{discarded_region_count});
    log.debug("Original entry count: {}. Actual region count: {}", .{ memory_map_entries.len, actual_memory_map_entry_count });

    var extra_size: u32 = 0;
    const length_size_tuples = blk: {
        var arr = [1]struct { length: u32, size: u32 }{.{ .length = 0, .size = 0 }} ** bootloader.Information.Slice.count;
        arr[@enumToInt(bootloader.Information.Slice.Name.memory_map_entries)].length = actual_memory_map_entry_count;
        arr[@enumToInt(bootloader.Information.Slice.Name.page_counters)].length = actual_memory_map_entry_count;
        arr[@enumToInt(bootloader.Information.Slice.Name.external_bootloader_page_counters)].length = actual_memory_map_entry_count;
        arr[@enumToInt(bootloader.Information.Slice.Name.cpu_driver_stack)].length = stack_size;
        arr[@enumToInt(bootloader.Information.Slice.Name.cpus)].length = cpu_count;

        inline for (bootloader.Information.Slice.TypeMap) |T, index| {
            const size = arr[index].length * @sizeOf(T);
            extra_size += size;
            arr[index].size = size;
        }
        break :blk arr;
    };
    _ = length_size_tuples;

    const aligned_struct_size = bootloader.Information.getStructAlignedSizeOnCurrentArchitecture();
    const aligned_extra_size = lib.alignForward(extra_size, lib.arch.valid_page_sizes[0]);
    const total_size = aligned_struct_size + aligned_extra_size;

    const bootloader_information = memory_map_entries[unmergeable_usable_region].region.address.toIdentityMappedVirtualAddress().access(*bootloader.Information);
    _ = bootloader_information;
    log.debug("Total size: 0x{x}", .{total_size});

    stopCPU();
}

export var limine_information = BootloaderInfo.Request{ .revision = 0 };
export var limine_stack_size = StackSize.Request{ .revision = 0, .stack_size = 0x4000 };
export var limine_hhdm = HHDM.Request{ .revision = 0 };
export var limine_framebuffer = Framebuffer.Request{ .revision = 0 };
export var limine_smp = SMPInfoRequest{ .revision = 0, .flags = .{ .x2apic = false } };
export var limine_memory_map = MemoryMap.Request{ .revision = 0 };
export var limine_entry_point = EntryPoint.Request{ .revision = 0, .entry_point = limineEntryPoint };
export var limine_kernel_file = KernelFile.Request{ .revision = 0 };
export var limine_modules = Module.Request{ .revision = 0 };
export var limine_rsdp = RSDP.Request{ .revision = 0 };
