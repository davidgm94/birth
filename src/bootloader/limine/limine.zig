pub const Installer = @import("installer.zig");

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
        framebuffers: *const [*]const Framebuffer,
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
        region: PhysicalMemoryRegion(.global),
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

const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.LIMINE);

const bootloader = @import("bootloader");

const privileged = @import("privileged");
const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const VirtualAddress = privileged.VirtualAddress;
const VirtualAddressSpace = privileged.VirtualAddressSpace;
const stopCPU = privileged.arch.stopCPU;

fn mapSection(bootloader_information: *bootloader.Information, comptime section_name: []const u8, flags: VirtualAddressSpace.Flags) !void {
    const section_start_symbol = @extern(*u8, .{ .name = section_name ++ "_section_start" });
    const section_end_symbol = @extern(*u8, .{ .name = section_name ++ "_section_end" });
    const section_start = @ptrToInt(section_start_symbol);
    const section_end = @ptrToInt(section_end_symbol);
    const section_size = section_end - section_start;
    log.debug("Section: {s}. Start: 0x{x}. End: 0x{x}. Size: 0x{x}", .{ section_name, section_start, section_end, section_size });

    const virtual_address = VirtualAddress(.local).new(section_start);
    const physical_address = PhysicalAddress(.local).new(virtual_address.value() - limine_kernel_address.response.?.virtual_address + limine_kernel_address.response.?.physical_address);
    // log.debug("Mapping cpu driver section {s} (0x{x} - 0x{x}) for 0x{x} bytes", .{ section_name, physical_address.value(), virtual_address.value(), size });
    bootloader_information.virtual_address_space.map(.local, physical_address, virtual_address, section_size, flags) catch @panic("Mapping of section failed");

    @field(bootloader_information.cpu_driver_mappings, section_name) = .{
        .physical = physical_address,
        .virtual = virtual_address,
        .size = section_size,
        .flags = flags,
    };
}

var limine_information = BootloaderInfo.Request{ .revision = 0 };
var limine_stack_size = StackSize.Request{ .revision = 0, .stack_size = privileged.default_stack_size };
var limine_hhdm = HHDM.Request{ .revision = 0 };
var limine_framebuffer = Framebuffer.Request{ .revision = 0 };
var limine_smp = SMPInfoRequest{ .revision = 0, .flags = .{ .x2apic = false } };
var limine_memory_map = MemoryMap.Request{ .revision = 0 };
var limine_entry_point = EntryPoint.Request{ .revision = 0, .entry_point = limineEntryPoint };
var limine_kernel_file = KernelFile.Request{ .revision = 0 };
var limine_kernel_address = KernelAddress.Request{ .revision = 0 };
var limine_modules = Module.Request{ .revision = 0 };
var limine_rsdp = RSDP.Request{ .revision = 0 };
var limine_smbios = SMBIOS.Request{ .revision = 0 };
var limine_efi_system_table = EFISystemTable.Request{ .revision = 0 };

comptime {
    if (lib.os == .freestanding) {
        @export(limine_information, .{ .name = "limine_information", .linkage = .Strong });
        @export(limine_stack_size, .{ .name = "limine_stack_size", .linkage = .Strong });
        @export(limine_hhdm, .{ .name = "limine_hhdm", .linkage = .Strong });
        @export(limine_framebuffer, .{ .name = "limine_framebuffer", .linkage = .Strong });
        @export(limine_smp, .{ .name = "limine_smp", .linkage = .Strong });
        @export(limine_memory_map, .{ .name = "limine_memory_map", .linkage = .Strong });
        @export(limine_entry_point, .{ .name = "limine_entry_point", .linkage = .Strong });
        @export(limine_kernel_file, .{ .name = "limine_kernel_file", .linkage = .Strong });
        @export(limine_kernel_address, .{ .name = "limine_kernel_address", .linkage = .Strong });
        @export(limine_modules, .{ .name = "limine_modules", .linkage = .Strong });
        @export(limine_rsdp, .{ .name = "limine_rsdp", .linkage = .Strong });
        @export(limine_smbios, .{ .name = "limine_smbios", .linkage = .Strong });
        @export(limine_efi_system_table, .{ .name = "limine_efi_system_table", .linkage = .Strong });
    }
}

extern fn limineEntryPoint() callconv(.C) noreturn;

pub fn entryPoint() callconv(.C) noreturn {
    log.debug("Hello from Limine {s}!", .{limine_information.response.?.version});
    const limine_protocol: bootloader.Protocol = blk: {
        if (limine_efi_system_table.response != null) break :blk .uefi;
        if (limine_smbios.response != null) break :blk .bios;

        @panic("undefined protocol");
    };

    // TODO: fetch files
    const module_count = @intCast(u32, limine_modules.response.?.module_count);
    log.warn("TODO: fetch files", .{});

    const limine_module_response = limine_modules.response.?;
    const limine_module_slice = limine_module_response.modules.?.*[0..limine_module_response.module_count];
    const file_alignment = 0x200;
    var aligned_total_file_size: u32 = 0;
    var total_name_size: u32 = 0;
    {
        for (limine_module_slice) |module_descriptor| {
            const file_size = @intCast(u32, module_descriptor.size);
            aligned_total_file_size += lib.alignForwardGeneric(u32, file_size, file_alignment);

            total_name_size += @intCast(u32, lib.length(module_descriptor.path));

            log.debug("Path: {s}", .{module_descriptor.path});
        }
    }

    const framebuffer = &limine_framebuffer.response.?.framebuffers.*[0];
    assert(limine_stack_size.response != null);
    log.debug("CPU count: {}", .{limine_smp.response.?.cpu_count});
    const memory_map = limine_memory_map.response.?;
    log.debug("Memory map entry count: {}", .{memory_map.entry_count});
    const memory_map_entries = memory_map.entries.?.*[0..memory_map.entry_count];

    const cpu_count = @intCast(u32, limine_smp.response.?.cpu_count);
    const memory_map_entry_count = @intCast(u32, memory_map_entries.len);

    const length_size_tuples = bootloader.LengthSizeTuples.new(.{
        .bootloader_information = .{
            .length = 1,
            .alignment = @alignOf(bootloader.Information),
        },
        .file_contents = .{
            .length = aligned_total_file_size,
            .alignment = file_alignment,
        },
        .file_names = .{
            .length = total_name_size,
            .alignment = 1,
        },
        .files = .{
            .length = module_count,
            .alignment = @alignOf(bootloader.File),
        },
        .memory_map_entries = .{
            .length = memory_map_entry_count,
            .alignment = @alignOf(bootloader.MemoryMapEntry),
        },
        .page_counters = .{
            .length = memory_map_entry_count,
            .alignment = @alignOf(u32),
        },
        .smps = .{
            .length = cpu_count,
            .alignment = @alignOf(bootloader.Information.SMP.Information),
        },
    });

    var entry_index: usize = 0;
    const bootloader_information = for (memory_map_entries, 0..) |entry, index| {
        if (entry.type == .usable and entry.region.size > length_size_tuples.getAlignedTotalSize()) {
            const bootloader_information_region = entry.region.takeSlice(length_size_tuples.getAlignedTotalSize());
            log.debug("Bootloader information region: 0x{x}-0x{x}", .{ entry.region.address.value(), entry.region.address.offset(entry.region.size).value() });
            log.debug("Bootloader information region slice: 0x{x}-0x{x}", .{ bootloader_information_region.address.value(), bootloader_information_region.address.offset(bootloader_information_region.size).value() });
            const bootloader_information = bootloader_information_region.address.toIdentityMappedVirtualAddress().access(*bootloader.Information);
            bootloader_information.* = .{
                .total_size = length_size_tuples.total_size,
                .entry_point = @ptrToInt(&@import("root").entryPoint),
                .higher_half = lib.config.cpu_driver_higher_half_address,
                .version = version: {
                    const limine_version = limine_information.response.?.version[0..lib.length(limine_information.response.?.version)];
                    var token_iterator = lib.tokenize(u8, limine_version, ".");
                    const version_major_string = token_iterator.next() orelse @panic("Limine version major");
                    const version_minor_string = token_iterator.next() orelse @panic("Limine version minor");
                    const version_patch_string = token_iterator.next() orelse @panic("Limine version patch");
                    if (token_iterator.next() != null) @panic("Unexpected token in Limine version");

                    const version_major = lib.parseUnsigned(u8, version_major_string, 10) catch @panic("Limine version major parsing");
                    if (version_minor_string.len != 4 + 2 + 2) @panic("Unexpected version minor length");
                    const version_minor_year_string = version_minor_string[0..4];
                    const version_minor_month_string = version_minor_string[4..6];
                    const version_minor_day_string = version_minor_string[6..8];
                    const version_minor_year = @intCast(u7, (lib.parseUnsigned(u16, version_minor_year_string, 10) catch @panic("Limine version minor year parsing")) - 1970);
                    const version_minor_month = lib.parseUnsigned(u4, version_minor_month_string, 10) catch @panic("Limine version minor month parsing");
                    const version_minor_day = lib.parseUnsigned(u5, version_minor_day_string, 10) catch @panic("Limine version minor day parsing");
                    const version_patch = lib.parseUnsigned(u8, version_patch_string, 10) catch @panic("Limine version patch parsing");

                    const version_minor = bootloader.CompactDate{
                        .year = version_minor_year,
                        .month = version_minor_month,
                        .day = version_minor_day,
                    };

                    break :version .{
                        .major = version_major,
                        .minor = @bitCast(u16, version_minor),
                        .patch = version_patch,
                    };
                },
                .protocol = limine_protocol,
                .bootloader = .limine,
                .stage = .early,
                .configuration = .{
                    .memory_map_diff = 0,
                },
                .heap = .{},
                .cpu_driver_mappings = .{},
                .smp = switch (lib.cpu.arch) {
                    .x86_64 => .{
                        .cpu_count = cpu_count,
                        .bsp_lapic_id = limine_smp.response.?.bsp_lapic_id,
                    },
                    .aarch64 => .{
                        .cpu_count = cpu_count,
                    },
                    else => @compileError("Architecture not supported"),
                },
                .framebuffer = .{
                    .address = framebuffer.address,
                    .pitch = @intCast(u32, framebuffer.pitch),
                    .width = @intCast(u32, framebuffer.width),
                    .height = @intCast(u32, framebuffer.height),
                    .bpp = framebuffer.bpp,
                    .red_mask = .{
                        .shift = framebuffer.red_mask_shift,
                        .size = framebuffer.red_mask_size,
                    },
                    .green_mask = .{
                        .shift = framebuffer.green_mask_shift,
                        .size = framebuffer.green_mask_size,
                    },
                    .blue_mask = .{
                        .shift = framebuffer.blue_mask_shift,
                        .size = framebuffer.blue_mask_size,
                    },
                    .memory_model = framebuffer.memory_model,
                },
                .draw_context = .{},
                .font = undefined,
                .architecture = switch (lib.cpu.arch) {
                    .x86_64 => .{
                        .rsdp_address = limine_rsdp.response.?.address,
                    },
                    .aarch64 => .{
                        .foo = 0,
                    },
                    else => @compileError("Architecture not supported"),
                },
                .slices = length_size_tuples.createSlices(),
                .virtual_address_space = undefined,
            };

            entry_index = index;

            break bootloader_information;
        }
    } else @panic("Unable to get bootloader information");

    const page_counters = bootloader_information.getSlice(.page_counters);

    for (page_counters) |*page_counter| {
        page_counter.* = 0;
    }

    page_counters[entry_index] = bootloader_information.getAlignedTotalSize() >> lib.arch.page_shifter(lib.arch.valid_page_sizes[0]);

    const bootloader_memory_map_entries = bootloader_information.getSlice(.memory_map_entries);
    for (memory_map_entries, 0..) |entry, index| {
        bootloader_memory_map_entries[index] = .{
            .region = entry.region,
            .type = switch (entry.type) {
                .usable => .usable,
                .framebuffer, .kernel_and_modules, .bootloader_reclaimable, .reserved, .acpi_reclaimable, .acpi_nvs => .reserved,
                .bad_memory => @panic("Bad memory"),
            },
        };

        const entry_page_count = @intCast(u32, entry.region.size >> lib.arch.page_shifter(lib.arch.valid_page_sizes[0]));
        if (entry.type != .usable) {
            // Reserved
            page_counters[index] = entry_page_count;
        }
    }

    // Copy files
    {
        var file_content_offset: u32 = 0;
        var file_name_offset: u32 = 0;
        // var file_index: usize = 0;
        // _ = file_index;
        const file_slice = bootloader_information.getSliceOffset(.files);
        const file_name_buffer = bootloader_information.getSlice(.file_names);
        _ = file_slice;
        var files = bootloader_information.getFiles();
        for (files, limine_module_slice) |*file, limine_file| {
            const file_size = @intCast(u32, limine_file.size);
            const limine_path = limine_file.path[0..lib.length(limine_file.path)];
            file.* = .{
                .content_offset = file_content_offset,
                .content_size = file_size,
                .path_offset = file_name_offset,
                .path_size = @intCast(u32, limine_path.len),
                .type = if (lib.containsAtLeast(u8, limine_path, 1, "cpu")) .cpu_driver else if (lib.containsAtLeast(u8, limine_path, 1, "font")) .font else if (lib.containsAtLeast(u8, limine_path, 1, "init")) .init else @panic("Unexpected file type"),
            };

            const limine_file_slice = @intToPtr([*]const u8, limine_file.address)[0..limine_file.size];
            file.copyContent(bootloader_information, limine_file_slice);

            const dst_file_name = file_name_buffer[file_name_offset .. file_name_offset + limine_path.len];
            lib.copy(u8, dst_file_name, limine_path);

            file_content_offset += lib.alignForwardGeneric(u32, file_size, file_alignment);
            file_name_offset += @intCast(u32, limine_path.len);
        }
    }

    bootloader_information.virtual_address_space = VirtualAddressSpace.paging.initKernelBSP(&bootloader_information.page_allocator) catch @panic("Virtual address space creation");

    for (bootloader_information.getMemoryMapEntries()) |entry| {
        if (entry.type == .usable) {
            log.debug("Usable memory map entry: 0x{x}-0x{x}", .{ entry.region.address.value(), entry.region.address.offset(entry.region.size).value() });
            bootloader_information.virtual_address_space.map(.global, entry.region.address, entry.region.address.toIdentityMappedVirtualAddress(), lib.alignForwardGeneric(u64, entry.region.size, lib.arch.valid_page_sizes[0]), .{ .write = true, .execute = true }) catch @panic("Mapping of usable memory map entry failed");
            bootloader_information.virtual_address_space.map(.global, entry.region.address, entry.region.address.toHigherHalfVirtualAddress(), lib.alignForwardGeneric(u64, entry.region.size, lib.arch.valid_page_sizes[0]), .{ .write = true, .execute = true }) catch @panic("Mapping of usable memory map entry failed");
        }
    }

    // Trust the Limine bootloader to merely use the higher half offset
    const framebuffer_physical_address = PhysicalAddress(.global).new(bootloader_information.framebuffer.address - lib.config.cpu_driver_higher_half_address);
    const framebuffer_virtual_address = VirtualAddress(.global).new(bootloader_information.framebuffer.address);
    log.debug("Framebuffer: 0x{x}", .{framebuffer_physical_address.value()});
    bootloader_information.virtual_address_space.map(.global, framebuffer_physical_address, framebuffer_virtual_address, lib.alignForwardGeneric(u64, bootloader_information.framebuffer.pitch * bootloader_information.framebuffer.height, lib.arch.valid_page_sizes[0]), .{ .write = true, .execute = false }) catch @panic("can't map framebuffer");

    const sections = &[_]struct { name: []const u8, flags: VirtualAddressSpace.Flags }{
        .{ .name = "text", .flags = .{ .write = false, .execute = true } },
        .{ .name = "rodata", .flags = .{ .write = false, .execute = false } },
        .{ .name = "data", .flags = .{ .write = true, .execute = false } },
    };

    inline for (sections) |section| {
        mapSection(bootloader_information, section.name, section.flags) catch @panic("Can't map cpu driver section");
    }

    // const bootloader_information_physical_address = PhysicalAddress(.local).new(@ptrToInt(bootloader_information));
    // const bootloader_information_virtual_address = bootloader_information_physical_address.toHigherHalfVirtualAddress();
    // log.debug("mapping 0x{x}-0x{x}", .{ bootloader_information_physical_address.value(), bootloader_information_virtual_address.value() });
    // VirtualAddressSpace.paging.map(&bootloader_information.virtual_address_space, .local, bootloader_information_physical_address, bootloader_information_virtual_address, bootloader_information.getAlignedTotalSize(), .{ .write = true, .execute = false }, &bootloader_information.page_allocator) catch @panic("Mapping of bootloader information failed");

    // Hack: map Limine stack to jump properly
    const rsp = switch (lib.cpu.arch) {
        .x86_64 => asm volatile (
            \\mov %rsp, %[result]
            : [result] "=r" (-> u64),
        ),
        .aarch64 => @panic("TODO stack"),
        else => @compileError("Architecture not supported"),
    };

    for (memory_map_entries) |entry| {
        if (entry.type == .bootloader_reclaimable) {
            if (entry.region.address.toHigherHalfVirtualAddress().value() < rsp and entry.region.address.offset(entry.region.size).toHigherHalfVirtualAddress().value() > rsp) {
                bootloader_information.virtual_address_space.map(.global, entry.region.address, entry.region.address.toHigherHalfVirtualAddress(), entry.region.size, .{ .write = true, .execute = false }) catch @panic("Mapping of bootloader information failed");
                break;
            }
        }
    } else @panic("Can't find memory map region for RSP");

    switch (lib.cpu.arch) {
        .x86_64 => bootloader.arch.x86_64.jumpToKernel(bootloader_information),
        .aarch64 => while (true) {},
        else => @compileError("Architecture not supported"),
    }
}
