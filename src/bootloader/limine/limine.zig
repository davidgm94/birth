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
        region: PhysicalMemoryRegion,
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
const Mapping = privileged.Mapping;
const PageAllocator = privileged.PageAllocator;
const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const VirtualAddress = privileged.VirtualAddress;
const stopCPU = privileged.arch.stopCPU;
const paging = privileged.arch.x86_64.paging;

fn mapSection(minimal_paging: paging.Specific, page_allocator: PageAllocator, comptime section_name: []const u8, flags: Mapping.Flags) !void {
    const section_start_symbol = @extern(*u8, .{ .name = section_name ++ "_section_start" });
    const section_end_symbol = @extern(*u8, .{ .name = section_name ++ "_section_end" });
    const section_start = @ptrToInt(section_start_symbol);
    const section_end = @ptrToInt(section_end_symbol);
    const section_size = section_end - section_start;
    log.debug("Section: {s}. Start: 0x{x}. End: 0x{x}. Size: 0x{x}", .{ section_name, section_start, section_end, section_size });

    const virtual_address = VirtualAddress.new(section_start);
    const physical_address = PhysicalAddress.new(virtual_address.value() - limine_kernel_address.response.?.virtual_address + limine_kernel_address.response.?.physical_address);
    // log.debug("Mapping cpu driver section {s} (0x{x} - 0x{x}) for 0x{x} bytes", .{ section_name, physical_address.value(), virtual_address.value(), size });
    try minimal_paging.map(physical_address, virtual_address, section_size, flags, page_allocator);
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
    main() catch |err| @panic(@errorName(err));
}

const Filesystem = extern struct {
    module_ptr: [*]const File,
    module_count: usize,
    index: usize,

    fn initialize(context: ?*anyopaque) anyerror!void {
        const filesystem = @ptrCast(*Filesystem, @alignCast(@alignOf(Filesystem), context));
        const limine_module_response = limine_modules.response.?;
        filesystem.* = .{
            .module_ptr = limine_module_response.modules.?.*,
            .module_count = limine_module_response.module_count,
            .index = 0,
        };
    }

    fn deinitialize(context: ?*anyopaque) anyerror!void {
        const filesystem = @ptrCast(*Filesystem, @alignCast(@alignOf(Filesystem), context));
        filesystem.index = 0;
    }

    const Error = error{
        not_found,
    };

    fn getFileDescriptor(context: ?*anyopaque, file_type: bootloader.File.Type) anyerror!bootloader.Information.Initialization.Filesystem.Descriptor {
        const filesystem = @ptrCast(*Filesystem, @alignCast(@alignOf(Filesystem), context));
        const modules = filesystem.module_ptr[0..filesystem.module_count];
        for (modules) |module| {
            const path = module.path[0..lib.length(module.path)];

            if (lib.containsAtLeast(u8, path, 1, @tagName(file_type))) {
                const size = @intCast(u32, module.size);
                return .{
                    .path = path,
                    .size = size,
                    .type = file_type,
                };
            }
        }

        return Error.not_found;
    }

    fn readFile(context: ?*anyopaque, file_path: []const u8, file_buffer: []u8) anyerror![]const u8 {
        const filesystem = @ptrCast(*Filesystem, @alignCast(@alignOf(Filesystem), context));
        for (filesystem.module_ptr[0..filesystem.module_count]) |module| {
            const path = module.path[0..lib.length(module.path)];
            if (lib.equal(u8, file_path, path)) {
                assert(file_buffer.len >= module.size);
                lib.copy(u8, file_buffer, @intToPtr([*]const u8, module.address)[0..module.size]);
                return file_buffer;
            }
        }

        @panic("readFile: can't find file with such path");
    }

    fn getFileSize(context: ?*anyopaque, file_path: []const u8) anyerror!u32 {
        _ = file_path;
        _ = context;
        @panic("TODO: getFileSize");
    }
};

const MMap = extern struct {
    entry_ptr: [*]const MemoryMap.Entry,
    entry_count: u32,
    index: u32 = 0,

    fn getMemoryMapEntryCount(context: ?*anyopaque) anyerror!u32 {
        const mmap = @ptrCast(*MMap, @alignCast(@alignOf(MMap), context));
        return mmap.entry_count;
    }

    fn initialize(context: ?*anyopaque) anyerror!void {
        const mmap = @ptrCast(*MMap, @alignCast(@alignOf(MMap), context));
        const memory_map = limine_memory_map.response.?;
        const memory_map_entries = memory_map.entries.?.*[0..memory_map.entry_count];
        mmap.* = .{
            .entry_ptr = memory_map_entries.ptr,
            .entry_count = @intCast(u32, memory_map_entries.len),
        };
    }

    fn deinitialize(context: ?*anyopaque) anyerror!void {
        const mmap = @ptrCast(*MMap, @alignCast(@alignOf(MMap), context));
        mmap.index = 0;
    }

    fn next(context: ?*anyopaque) anyerror!?bootloader.MemoryMapEntry {
        const mmap = @ptrCast(*MMap, @alignCast(@alignOf(MMap), context));

        if (mmap.index < mmap.entry_count) {
            const entry = mmap.entry_ptr[mmap.index];
            mmap.index += 1;

            return .{
                .region = entry.region,
                .type = switch (entry.type) {
                    .usable => .usable,
                    .framebuffer, .kernel_and_modules, .bootloader_reclaimable, .reserved, .acpi_reclaimable, .acpi_nvs => .reserved,
                    .bad_memory => @panic("Bad memory"),
                },
            };
        }

        return null;
    }
};

const FB = extern struct {
    fn initialize(context: ?*anyopaque) anyerror!bootloader.Framebuffer {
        _ = context;
        const framebuffer = &limine_framebuffer.response.?.framebuffers.*[0];
        return .{
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
        };
    }
};

const VirtualAddressSpace = extern struct {};

const VAS = extern struct {
    fn ensureLoaderIsMapped(context: ?*anyopaque, minimal_paging: privileged.arch.paging.Specific, page_allocator: PageAllocator, bootloader_information: *bootloader.Information) anyerror!void {
        _ = page_allocator;
        _ = bootloader_information;
        _ = context;
        _ = minimal_paging;
        // const sections = &[_]struct { name: []const u8, flags: Mapping.Flags }{
        //     .{ .name = "text", .flags = .{ .write = false, .execute = true } },
        //     .{ .name = "rodata", .flags = .{ .write = false, .execute = false } },
        //     .{ .name = "data", .flags = .{ .write = true, .execute = false } },
        // };
        //
        // inline for (sections) |section| {
        //     try mapSection(minimal_paging, page_allocator, section.name, section.flags);
        // }
    }

    fn ensureStackIsMapped(context: ?*anyopaque, minimal_paging: paging.Specific, page_allocator: PageAllocator) anyerror!void {
        _ = context;
        const rsp = switch (lib.cpu.arch) {
            .x86_64 => asm volatile (
                \\mov %rsp, %[result]
                : [result] "=r" (-> u64),
            ),
            .aarch64 => @panic("TODO stack"),
            else => @compileError("Architecture not supported"),
        };

        const memory_map = limine_memory_map.response.?;
        const memory_map_entries = memory_map.entries.?.*[0..memory_map.entry_count];
        for (memory_map_entries) |entry| {
            if (entry.type == .bootloader_reclaimable) {
                if (entry.region.address.toHigherHalfVirtualAddress().value() < rsp and entry.region.address.offset(entry.region.size).toHigherHalfVirtualAddress().value() > rsp) {
                    minimal_paging.map(entry.region.address, entry.region.address.toHigherHalfVirtualAddress(), entry.region.size, .{ .write = true, .execute = false }, page_allocator) catch @panic("Mapping of bootloader information failed");
                    break;
                }
            }
        } else @panic("Can't find memory map region for RSP");
    }
};

pub fn main() !noreturn {
    log.debug("Limine start", .{});
    var filesystem: Filesystem = undefined;
    var memory_map: MMap = undefined;
    const rsdp = @intToPtr(*privileged.ACPI.RSDP.Descriptor1, limine_rsdp.response.?.address);
    const limine_protocol: bootloader.Protocol = blk: {
        if (limine_efi_system_table.response != null) break :blk .uefi;
        if (limine_smbios.response != null) break :blk .bios;

        @panic("undefined protocol");
    };

    try bootloader.Information.initialize(.{
        .context = &filesystem,
        .initialize = Filesystem.initialize,
        .deinitialize = Filesystem.deinitialize,
        .get_file_descriptor = Filesystem.getFileDescriptor,
        .read_file = Filesystem.readFile,
    }, .{
        .context = &memory_map,
        .get_memory_map_entry_count = MMap.getMemoryMapEntryCount,
        .initialize = MMap.initialize,
        .deinitialize = MMap.deinitialize,
        .next = MMap.next,
        .get_host_region = null,
    }, .{
        .context = null,
        .initialize = FB.initialize,
    }, .{
        .context = null,
        .ensure_loader_is_mapped = VAS.ensureLoaderIsMapped,
        .ensure_stack_is_mapped = VAS.ensureStackIsMapped,
    }, rsdp, .limine, limine_protocol);
}
