const lib = @import("lib");
const assert = lib.assert;
const config = lib.config;
const Allocator = lib.Allocator;
const ELF = lib.ELF(64);
const log = lib.log.scoped(.uefi);
const PhysicalAddress = lib.PhysicalAddress;
const PhysicalMemoryRegion = lib.PhysicalMemoryRegion;
const VirtualAddress = lib.VirtualAddress;
const VirtualMemoryRegion = lib.VirtualMemoryRegion;

const bootloader = @import("bootloader");
const uefi = @import("uefi");
const BootloaderInformation = uefi.BootloaderInformation;
const BootServices = uefi.BootServices;
const ConfigurationTable = uefi.ConfigurationTable;
const FileProtocol = uefi.FileProtocol;
const Handle = uefi.Handle;
const LoadedImageProtocol = uefi.LoadedImageProtocol;
const LoadKernelFunction = uefi.LoadKernelFunction;
const MemoryCategory = uefi.MemoryCategory;
const MemoryDescriptor = uefi.MemoryDescriptor;
const ProgramSegment = uefi.ProgramSegment;
const Protocol = uefi.Protocol;
const page_table_estimated_size = uefi.page_table_estimated_size;
const SimpleFilesystemProtocol = uefi.SimpleFilesystemProtocol;
const SystemTable = uefi.SystemTable;

const privileged = @import("privileged");
const ACPI = privileged.ACPI;
const PageAllocator = privileged.PageAllocator;
pub const writer = privileged.writer;

const CPU = privileged.arch.CPU;
const GDT = privileged.arch.x86_64.GDT;
const paging = privileged.arch.paging;

const Stage = enum {
    boot_services,
    after_boot_services,
    trampoline,
};

pub const std_options = struct {
    pub const log_level = lib.std.log.Level.debug;

    pub fn logFn(comptime level: lib.std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
        const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
        switch (lib.cpu.arch) {
            .x86_64 => {
                lib.format(writer, prefix ++ format ++ "\n", args) catch {};
            },
            else => @compileError("Unsupported CPU architecture"),
        }
    }
};

const practical_memory_map_descriptor_size = 0x30;
const practical_memory_map_descriptor_count = 256;

pub fn panic(message: []const u8, _: ?*lib.StackTrace, _: ?usize) noreturn {
    writer.writeAll("[uefi] [PANIC] ") catch {};
    writer.writeAll(message) catch {};
    writer.writeAll("\r\n") catch {};

    privileged.shutdown(.failure);
}

const Filesystem = extern struct {
    root: *FileProtocol,
    buffer: [0x200 * 10]u8 = undefined,

    pub fn deinitialize(filesystem: *Filesystem) !void {
        _ = filesystem;
    }

    pub fn readFile(filesystem: *Filesystem, file_path: []const u8, file_buffer: []u8) ![]const u8 {
        const file = try filesystem.openFile(file_path);
        var size: u64 = file_buffer.len;
        try uefi.Try(file.handle.read(&size, file_buffer.ptr));
        if (file_buffer.len < size) @panic("readFileFast");
        return file_buffer[0..size];
    }

    pub fn sneakFile(filesystem: *Filesystem, file_path: []const u8, size: usize) ![]const u8 {
        _ = size;

        const file = try filesystem.readFile(file_path, &filesystem.buffer);
        return file;
    }

    const FileDescriptor = struct {
        handle: *FileProtocol,
        path_size: u32,
    };

    pub fn getFileSize(filesystem: *Filesystem, file_path: []const u8) !u32 {
        const file = try filesystem.openFile(file_path);
        log.debug("File size", .{});
        var file_info_buffer: [@sizeOf(uefi.FileInfo) + 0x100]u8 align(@alignOf(uefi.FileInfo)) = undefined;
        var file_info_size = file_info_buffer.len;
        try uefi.Try(file.handle.getInfo(&uefi.FileInfo.guid, &file_info_size, &file_info_buffer));
        if (file_info_buffer.len < file_info_size) @panic("getFileSize");
        const file_info = @as(*uefi.FileInfo, @ptrCast(&file_info_buffer));
        return @as(u32, @intCast(file_info.file_size));
    }

    fn openFile(filesystem: *Filesystem, file_path: []const u8) !FileDescriptor {
        const init = @fieldParentPtr(Initialization, "filesystem", filesystem);
        if (init.exited_boot_services) {
            return Error.boot_services_exited;
        }

        log.debug("opening file: {s}", .{file_path});
        var file: *FileProtocol = undefined;
        var path_buffer: [256:0]u16 = undefined;
        const length = try lib.unicode.utf8ToUtf16Le(&path_buffer, file_path);
        path_buffer[length] = 0;
        const path = path_buffer[0..length :0];
        const uefi_path = if (path[0] == '/') path[1..] else path;
        log.debug("uefi path: {any}", .{uefi_path});

        try uefi.Try(filesystem.root.open(&file, uefi_path, FileProtocol.efi_file_mode_read, 0));
        log.debug("Opened", .{});

        const result = FileDescriptor{
            .handle = file,
            .path_size = @as(u32, @intCast(path.len * @sizeOf(u16))),
        };

        log.debug("opened file: {s}", .{file_path});

        return result;
    }

    pub fn getSectorSize(filesystem: *Filesystem) u16 {
        _ = filesystem;
        return lib.default_sector_size;
    }
};

const MemoryMap = extern struct {
    size: usize = buffer_len,
    key: usize,
    descriptor_size: usize,
    descriptor_version: u32,
    buffer: [buffer_len]u8 align(@alignOf(MemoryDescriptor)) = undefined,
    offset: usize = 0,
    entry_count: u32,

    const buffer_len = practical_memory_map_descriptor_size * practical_memory_map_descriptor_count;

    pub fn getEntryCount(memory_map: *const MemoryMap) u32 {
        return memory_map.entry_count;
    }

    pub fn next(memory_map: *MemoryMap) !?bootloader.MemoryMapEntry {
        if (memory_map.offset < memory_map.size) {
            const entry = @as(*MemoryDescriptor, @ptrCast(@alignCast(@alignOf(MemoryDescriptor), memory_map.buffer[memory_map.offset..].ptr))).*;
            memory_map.offset += memory_map.descriptor_size;
            const result = bootloader.MemoryMapEntry{
                .region = PhysicalMemoryRegion.new(.{
                    .address = PhysicalAddress.new(entry.physical_start),
                    .size = entry.number_of_pages << uefi.page_shifter,
                }),
                .type = switch (entry.type) {
                    .ReservedMemoryType, .LoaderCode, .LoaderData, .BootServicesCode, .BootServicesData, .RuntimeServicesCode, .RuntimeServicesData, .ACPIReclaimMemory, .ACPIMemoryNVS, .MemoryMappedIO, .MemoryMappedIOPortSpace, .PalCode, .PersistentMemory => .reserved,
                    .ConventionalMemory => .usable,
                    .UnusableMemory => .bad_memory,
                    else => @panic("Unknown type"),
                },
            };

            return result;
        }

        return null;
    }

    fn getHostRegion(memory_map: *MemoryMap, length_size_tuples: bootloader.LengthSizeTuples) !PhysicalMemoryRegion {
        var memory: []align(uefi.page_size) u8 = undefined;
        const memory_size = length_size_tuples.getAlignedTotalSize();
        try uefi.Try(memory_map.boot_services.allocatePages(.AllocateAnyPages, .LoaderData, memory_size >> uefi.page_shifter, &memory.ptr));
        memory.len = memory_size;
        @memset(memory, 0);

        return PhysicalMemoryRegion.fromByteSlice(.{ .slice = memory });
    }
};

const Initialization = struct {
    filesystem: Filesystem,
    framebuffer: bootloader.Framebuffer,
    architecture: switch (lib.cpu.arch) {
        .x86_64 => struct {
            rsdp: *ACPI.RSDP.Descriptor1,
        },
        else => @compileError("Architecture not supported"),
    },
    boot_services: *uefi.BootServices,
    handle: uefi.Handle,
    // system_table: *uefi.SystemTable,
    early_initialized: bool = false,
    filesystem_initialized: bool = false,
    memory_map_initialized: bool = false,
    framebuffer_initialized: bool = false,
    exited_boot_services: bool = false,
    memory_map: MemoryMap,

    pub fn getRSDPAddress(init: *Initialization) u32 {
        return @as(u32, @intCast(@intFromPtr(init.architecture.rsdp)));
    }

    pub fn getCPUCount(init: *Initialization) !u32 {
        return switch (lib.cpu.arch) {
            .x86_64 => blk: {
                const madt_header = try init.architecture.rsdp.findTable(.APIC);
                const madt = @as(*align(1) const ACPI.MADT, @ptrCast(madt_header));
                break :blk madt.getCPUCount();
            },
            else => @compileError("Architecture not supported"),
        };
    }

    pub fn initialize(init: *Initialization) !void {
        defer init.early_initialized = true;

        const system_table = uefi.getSystemTable();
        const handle = uefi.getHandle();
        const boot_services = system_table.boot_services orelse @panic("boot services");
        const out = system_table.con_out orelse @panic("con out");
        try uefi.Try(out.reset(true));
        try uefi.Try(out.clearScreen());

        init.* = .{
            .memory_map = .{
                .key = 0,
                .descriptor_size = 0,
                .descriptor_version = 0,
                .entry_count = 0,
            },
            .filesystem = .{
                .root = blk: {
                    const loaded_image = try Protocol.open(LoadedImageProtocol, boot_services, handle);
                    const filesystem_protocol = try Protocol.open(SimpleFilesystemProtocol, boot_services, loaded_image.device_handle orelse @panic("No device handle"));

                    var root: *FileProtocol = undefined;
                    try uefi.Try(filesystem_protocol.openVolume(&root));
                    break :blk root;
                },
            },
            .framebuffer = blk: {
                log.debug("Locating GOP", .{});
                const gop = try Protocol.locate(uefi.GraphicsOutputProtocol, boot_services);
                log.debug("Located GOP", .{});

                const pixel_format_info: struct {
                    red_color_mask: bootloader.Framebuffer.ColorMask,
                    blue_color_mask: bootloader.Framebuffer.ColorMask,
                    green_color_mask: bootloader.Framebuffer.ColorMask,
                    bpp: u8,
                } = switch (gop.mode.info.pixel_format) {
                    .PixelRedGreenBlueReserved8BitPerColor => .{
                        .red_color_mask = .{ .size = 8, .shift = 0 },
                        .green_color_mask = .{ .size = 8, .shift = 8 },
                        .blue_color_mask = .{ .size = 8, .shift = 16 },
                        .bpp = 32,
                    },
                    .PixelBlueGreenRedReserved8BitPerColor => .{
                        .red_color_mask = .{ .size = 8, .shift = 16 },
                        .green_color_mask = .{ .size = 8, .shift = 8 },
                        .blue_color_mask = .{ .size = 8, .shift = 0 },
                        .bpp = 32,
                    },
                    .PixelBitMask, .PixelBltOnly => @panic("Unsupported pixel format"),
                    .PixelFormatMax => @panic("Corrupted pixel format"),
                };

                break :blk bootloader.Framebuffer{
                    .address = gop.mode.frame_buffer_base,
                    .pitch = @divExact(gop.mode.info.pixels_per_scan_line * pixel_format_info.bpp, @bitSizeOf(u8)),
                    .width = gop.mode.info.horizontal_resolution,
                    .height = gop.mode.info.vertical_resolution,
                    .bpp = pixel_format_info.bpp,
                    .red_mask = pixel_format_info.red_color_mask,
                    .green_mask = pixel_format_info.green_color_mask,
                    .blue_mask = pixel_format_info.blue_color_mask,
                    .memory_model = 0x06,
                };
            },
            .boot_services = boot_services,
            .handle = handle,
            .architecture = switch (lib.cpu.arch) {
                .x86_64 => .{
                    .rsdp = for (system_table.configuration_table[0..system_table.number_of_table_entries]) |configuration_table| {
                        if (configuration_table.vendor_guid.eql(ConfigurationTable.acpi_20_table_guid)) {
                            break @as(*ACPI.RSDP.Descriptor1, @ptrCast(@alignCast(@alignOf(ACPI.RSDP.Descriptor1), configuration_table.vendor_table)));
                        }
                    } else return Error.rsdp_not_found,
                },
                else => @compileError("Architecture not supported"),
            },
        };

        log.debug("Memory map size: {}", .{init.memory_map.size});
        _ = boot_services.getMemoryMap(&init.memory_map.size, @as([*]MemoryDescriptor, @ptrCast(&init.memory_map.buffer)), &init.memory_map.key, &init.memory_map.descriptor_size, &init.memory_map.descriptor_version);
        init.memory_map.entry_count = @as(u32, @intCast(@divExact(init.memory_map.size, init.memory_map.descriptor_size)));
        assert(init.memory_map.entry_count > 0);

        init.filesystem_initialized = true;
        init.memory_map_initialized = true;
        init.framebuffer_initialized = true;
    }

    pub fn deinitializeMemoryMap(init: *Initialization) !void {
        if (!init.exited_boot_services) {
            // Add the region for the bootloader information
            init.memory_map.size += init.memory_map.descriptor_size;
            const expected_memory_map_size = init.memory_map.size;
            const expected_memory_map_descriptor_size = init.memory_map.descriptor_size;
            const expected_memory_map_descriptor_version = init.memory_map.descriptor_version;

            log.debug("Getting memory map before exiting boot services...", .{});

            blk: while (init.memory_map.size < MemoryMap.buffer_len) : (init.memory_map.size += init.memory_map.descriptor_size) {
                uefi.Try(init.boot_services.getMemoryMap(&init.memory_map.size, @as([*]MemoryDescriptor, @ptrCast(&init.memory_map.buffer)), &init.memory_map.key, &init.memory_map.descriptor_size, &init.memory_map.descriptor_version)) catch continue;
                init.exited_boot_services = true;
                break :blk;
            } else {
                @panic("Cannot satisfy memory map requirements");
            }

            if (expected_memory_map_size != init.memory_map.size) {
                log.warn("Old memory map size: {}. New memory map size: {}", .{ expected_memory_map_size, init.memory_map.size });
            }
            if (expected_memory_map_descriptor_size != init.memory_map.descriptor_size) {
                @panic("Descriptor size change");
            }
            if (expected_memory_map_descriptor_version != init.memory_map.descriptor_version) {
                @panic("Descriptor version change");
            }
            const real_memory_map_entry_count = @divExact(init.memory_map.size, init.memory_map.descriptor_size);
            const expected_memory_map_entry_count = @divExact(expected_memory_map_size, expected_memory_map_descriptor_size);
            const diff = @as(i16, @intCast(expected_memory_map_entry_count)) - @as(i16, @intCast(real_memory_map_entry_count));
            if (diff < 0) {
                @panic("Memory map entry count diff < 0");
            }

            // bootloader_information.configuration.memory_map_diff = @intCast(u8, diff);

            log.debug("Exiting boot services...", .{});
            try uefi.Try(init.boot_services.exitBootServices(init.handle, init.memory_map.key));
            log.debug("Exited boot services...", .{});

            privileged.arch.disableInterrupts();
        }

        init.memory_map.offset = 0;
    }

    pub fn ensureLoaderIsMapped(init: *Initialization, minimal_paging: paging.Specific, page_allocator: PageAllocator, bootloader_information: *bootloader.Information) !void {
        _ = bootloader_information;
        // Actually mapping the whole uefi executable so we don't have random problems with code being dereferenced by the trampoline
        switch (lib.cpu.arch) {
            .x86_64 => {
                const trampoline_code_start = @intFromPtr(&bootloader.arch.x86_64.jumpToKernel);

                try init.deinitializeMemoryMap();
                while (try init.memory_map.next()) |entry| {
                    if (entry.region.address.value() < trampoline_code_start and trampoline_code_start < entry.region.address.offset(entry.region.size).value()) {
                        const code_physical_region = entry.region;
                        const code_virtual_address = code_physical_region.address.toIdentityMappedVirtualAddress();
                        try minimal_paging.map(code_physical_region.address, code_virtual_address, code_physical_region.size, .{ .write = false, .execute = true }, page_allocator);
                        return;
                    }
                }
            },
            else => @compileError("Architecture not supported"),
        }

        return Error.map_failed;
    }

    pub fn ensureStackIsMapped(init: *Initialization, minimal_paging: paging.Specific, page_allocator: PageAllocator) !void {
        const rsp = asm volatile (
            \\mov %rsp, %[rsp]
            : [rsp] "=r" (-> u64),
        );

        while (try init.memory_map.next()) |entry| {
            if (entry.region.address.value() < rsp and rsp < entry.region.address.offset(entry.region.size).value()) {
                const rsp_region_physical_address = entry.region.address;
                const rsp_region_virtual_address = rsp_region_physical_address.toIdentityMappedVirtualAddress();
                if (entry.region.size == 0) return Error.region_empty;
                try minimal_paging.map(rsp_region_physical_address, rsp_region_virtual_address, entry.region.size, .{ .write = true, .execute = false }, page_allocator);
                return;
            }
        }

        return Error.map_failed;
    }
};

var initialization: Initialization = undefined;

const Error = error{
    map_failed,
    region_empty,
    rsdp_not_found,
    boot_services_exited,
};

pub fn main() noreturn {
    // var filesystem: Filesystem = .{
    //     .boot_services = boot_services,
    //     .handle = handle,
    //     .root = undefined,
    // };
    // var mmap: MemoryMap = .{
    //     .boot_services = boot_services,
    //     .handle = handle,
    // };
    // var fb = Framebuffer{
    //     .boot_services = boot_services,
    // };
    // var vas = VAS{
    //     .mmap = &mmap,
    // };
    initialization.initialize() catch |err| {
        @panic(@errorName(err));
    };
    bootloader.Information.initialize(&initialization, .rise, .uefi) catch |err| {
        @panic(@errorName(err));
    };
}
