const lib = @import("lib");
const config = lib.config;
const Allocator = lib.Allocator;
const ELF = lib.ELF(64);
const log = lib.log.scoped(.UEFI);
const PhysicalAddress = lib.PhysicalAddress;
const PhysicalMemoryRegion = lib.PhysicalMemoryRegion;
const VirtualAddress = lib.VirtualAddress;
const VirtualMemoryRegion = lib.VirtualMemoryRegion;

const bootloader = @import("bootloader");
const UEFI = bootloader.UEFI;
const BootloaderInformation = UEFI.BootloaderInformation;
const BootServices = UEFI.BootServices;
const ConfigurationTable = UEFI.ConfigurationTable;
const FileProtocol = UEFI.FileProtocol;
const Handle = UEFI.Handle;
const LoadedImageProtocol = UEFI.LoadedImageProtocol;
const LoadKernelFunction = UEFI.LoadKernelFunction;
const MemoryCategory = UEFI.MemoryCategory;
const MemoryDescriptor = UEFI.MemoryDescriptor;
const ProgramSegment = UEFI.ProgramSegment;
const Protocol = UEFI.Protocol;
const page_table_estimated_size = UEFI.page_table_estimated_size;
const SimpleFilesystemProtocol = UEFI.SimpleFilesystemProtocol;
const SystemTable = UEFI.SystemTable;

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

pub fn panic(message: []const u8, _: ?*lib.StackTrace, _: ?usize) noreturn {
    writer.writeAll("[UEFI] [PANIC] ") catch {};
    writer.writeAll(message) catch {};
    writer.writeAll("\r\n") catch {};

    if (lib.is_test) {
        privileged.exitFromQEMU(.failure);
    } else {
        asm volatile (
            \\cli
            \\hlt
            ::: "memory");
        unreachable;
    }
}
pub var draw_writer: bootloader.DrawContext.Writer = undefined;

pub var maybe_bootloader_information: ?*bootloader.Information = null;
pub var boot_services_on = true;

var buffer: [0x200 * 10]u8 = undefined;

const Filesystem = extern struct {
    boot_services: *UEFI.BootServices,
    handle: UEFI.Handle,
    root: *FileProtocol,

    pub fn initialize(filesystem: *Filesystem) !void {
        const loaded_image = Protocol.open(LoadedImageProtocol, filesystem.boot_services, filesystem.handle);
        const filesystem_protocol = Protocol.open(SimpleFilesystemProtocol, filesystem.boot_services, loaded_image.device_handle orelse @panic("No device handle"));
        try UEFI.Try(filesystem_protocol.openVolume(&filesystem.root));
    }

    pub fn deinitialize(filesystem: *Filesystem) !void {
        _ = filesystem;
        // const filesystem = @ptrCast(*Filesystem, @alignCast(@alignOf(Filesystem), context));
        // _ = filesystem;
    }

    pub fn readFile(filesystem: *Filesystem, file_path: []const u8, file_buffer: []u8) ![]const u8 {
        const file = try filesystem.openFile(file_path);

        var size: u64 = file_buffer.len;

        try UEFI.Try(file.handle.read(&size, file_buffer.ptr));

        if (file_buffer.len < size) {
            @panic("readFileFast");
        }

        return file_buffer[0..size];
    }

    const FileDescriptor = struct {
        handle: *FileProtocol,
        path_size: u32,
    };

    pub fn sneakFile(filesystem: *Filesystem, file_path: []const u8, size: usize) ![]const u8 {
        const file = try filesystem.readFile(file_path, buffer[0..size]);
        return file;
    }

    pub fn getFileSize(filesystem: *Filesystem, file_path: []const u8) !u32 {
        const file = try filesystem.openFile(file_path);

        var file_info_buffer: [@sizeOf(UEFI.FileInfo) + 0x100]u8 align(@alignOf(UEFI.FileInfo)) = undefined;
        var file_info_size = file_info_buffer.len;

        try UEFI.Try(file.handle.getInfo(&UEFI.FileInfo.guid, &file_info_size, &file_info_buffer));

        if (file_info_buffer.len < file_info_size) {
            return Error.file_descriptor_buffer_not_big_enough;
        }

        const file_info = @ptrCast(*UEFI.FileInfo, &file_info_buffer);
        return @intCast(u32, file_info.file_size);
    }

    fn openFile(filesystem: *Filesystem, file_path: []const u8) !FileDescriptor {
        var file: *FileProtocol = undefined;
        var path_buffer: [256:0]u16 = undefined;
        const length = try lib.unicode.utf8ToUtf16Le(&path_buffer, file_path);
        path_buffer[length] = 0;
        const path = path_buffer[0..length :0];
        try UEFI.Try(filesystem.root.open(&file, if (path[0] == '/') path[1..] else path, FileProtocol.efi_file_mode_read, 0));

        return .{
            .handle = file,
            .path_size = @intCast(u32, path.len * @sizeOf(u16)),
        };
    }

    pub fn getDiskSectorSize(filesystem: *Filesystem) u16 {
        _ = filesystem;
        return lib.default_sector_size;
    }
};

const MemoryMap = extern struct {
    boot_services: *UEFI.BootServices,
    handle: UEFI.Handle,
    size: usize = buffer_len,
    key: usize,
    descriptor_size: usize,
    descriptor_version: u32,
    buffer: [buffer_len]u8 align(@alignOf(MemoryDescriptor)) = undefined,
    offset: usize = 0,

    const buffer_len = practical_memory_map_descriptor_size * practical_memory_map_descriptor_count;

    pub fn initialize(memory_map: *MemoryMap) !u32 {
        log.debug("Memory map size BEFORE: {}", .{memory_map.size});
        try UEFI.Try(memory_map.boot_services.getMemoryMap(&memory_map.size, @ptrCast([*]UEFI.MemoryDescriptor, &memory_map.buffer), &memory_map.key, &memory_map.descriptor_size, &memory_map.descriptor_version));
        log.debug("Memory map size AFTER: {}", .{memory_map.size});
        const entry_count = @intCast(u32, @divExact(memory_map.size, memory_map.descriptor_size));
        return entry_count;
    }

    pub fn next(memory_map: *MemoryMap) !?bootloader.MemoryMapEntry {
        if (memory_map.offset < memory_map.size) {
            const entry = @ptrCast(*MemoryDescriptor, @alignCast(@alignOf(MemoryDescriptor), memory_map.buffer[memory_map.offset..].ptr)).*;
            memory_map.offset += memory_map.descriptor_size;
            const result = bootloader.MemoryMapEntry{
                .region = PhysicalMemoryRegion.new(.{
                    .address = PhysicalAddress.new(entry.physical_start),
                    .size = entry.number_of_pages << UEFI.page_shifter,
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

    pub fn reset(memory_map: *MemoryMap) void {
        memory_map.offset = 0;
    }

    fn getMemoryMapEntryCount(memory_map: *MemoryMap) !u32 {
        // Return one more since we are expected to allocate a region for the bootloader information
        const result = @intCast(u32, @divExact(memory_map.size, memory_map.descriptor_size) + 1);
        return result;
    }

    pub fn deinitialize(memory_map: *MemoryMap) !void {
        log.debug("\n\nDEINIT\n\n", .{});
        if (boot_services_on) {
            defer boot_services_on = false;

            // Add the region for the bootloader information
            memory_map.size += 100 * memory_map.descriptor_size;
            const expected_memory_map_size = memory_map.size;
            const expected_memory_map_descriptor_size = memory_map.descriptor_size;
            const expected_memory_map_descriptor_version = memory_map.descriptor_version;

            while (true) : (memory_map.size += memory_map.descriptor_size) {
                log.debug("Getting memory map before exiting boot services...", .{});
                log.debug("Buffer size: {}", .{memory_map.size});

                UEFI.Try(memory_map.boot_services.getMemoryMap(&memory_map.size, @ptrCast([*]MemoryDescriptor, &memory_map.buffer), &memory_map.key, &memory_map.descriptor_size, &memory_map.descriptor_version)) catch continue;

                break;
            }

            if (expected_memory_map_size != memory_map.size) {
                log.warn("Old memory map size: {}. New memory map size: {}", .{ expected_memory_map_size, memory_map.size });
            }

            if (expected_memory_map_descriptor_size != memory_map.descriptor_size) {
                @panic("Descriptor size change");
            }

            if (expected_memory_map_descriptor_version != memory_map.descriptor_version) {
                @panic("Descriptor version change");
            }

            const real_memory_map_entry_count = @divExact(memory_map.size, memory_map.descriptor_size);
            const expected_memory_map_entry_count = @divExact(expected_memory_map_size, expected_memory_map_descriptor_size);
            const diff = @intCast(i16, expected_memory_map_entry_count) - @intCast(i16, real_memory_map_entry_count);

            if (diff < 0) {
                @panic("Memory map entry count diff < 0");
            }

            // bootloader_information.configuration.memory_map_diff = @intCast(u8, diff);

            log.debug("Exiting boot services...", .{});
            try UEFI.Try(memory_map.boot_services.exitBootServices(memory_map.handle, memory_map.key));
            log.debug("Exited boot services", .{});

            privileged.arch.disableInterrupts();
        }

        memory_map.offset = 0;
    }

    fn getHostRegion(memory_map: *MemoryMap, length_size_tuples: bootloader.LengthSizeTuples) !PhysicalMemoryRegion {
        var memory: []align(UEFI.page_size) u8 = undefined;
        const memory_size = length_size_tuples.getAlignedTotalSize();
        try UEFI.Try(memory_map.boot_services.allocatePages(.AllocateAnyPages, .LoaderData, memory_size >> UEFI.page_shifter, &memory.ptr));
        memory.len = memory_size;
        @memset(memory, 0);

        return PhysicalMemoryRegion.fromByteSlice(.{ .slice = memory });
    }
};

const Framebuffer = extern struct {
    boot_services: *UEFI.BootServices,

    pub fn initialize(framebuffer: *Framebuffer) !bootloader.Framebuffer {
        const gop = try Protocol.locate(UEFI.GraphicsOutputProtocol, framebuffer.boot_services);
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

        return bootloader.Framebuffer{
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
    }
};

const VirtualAddressSpace = extern struct {
    mmap: *anyopaque,

    pub fn ensureLoaderIsMapped(virtual_address_space: *VirtualAddressSpace, minimal_paging: paging.Specific, page_allocator: PageAllocator, bootloader_information: *bootloader.Information, memory_map: *MemoryMap) !void {
        _ = bootloader_information;
        _ = virtual_address_space;

        log.debug("Ensuring loader is mapped", .{});
        // Actually mapping the whole UEFI executable so we don't have random problems with code being dereferenced by the trampoline
        switch (lib.cpu.arch) {
            .x86_64 => {
                const trampoline_code_start = @ptrToInt(&bootloader.arch.x86_64.jumpToKernel);

                try memory_map.deinitialize();
                while (try memory_map.next()) |entry| {
                    if (entry.region.address.value() < trampoline_code_start and trampoline_code_start < entry.region.address.offset(entry.region.size).value()) {
                        const code_physical_region = entry.region;
                        const code_virtual_address = code_physical_region.address.toIdentityMappedVirtualAddress();
                        try minimal_paging.map(code_physical_region.address, code_virtual_address, code_physical_region.size, .{ .write = false, .execute = true }, page_allocator);
                        log.debug("Ended ensuring loader is mapped", .{});
                        return;
                    }
                }
            },
            else => @compileError("Architecture not supported"),
        }

        return Error.map_failed;
    }

    pub fn ensureStackIsMapped(virtual_address_space: *VirtualAddressSpace, minimal_paging: paging.Specific, page_allocator: PageAllocator, memory_map: *MemoryMap) !void {
        _ = virtual_address_space;
        log.debug("Ensuring stack is mapped", .{});
        const rsp = asm volatile (
            \\mov %rsp, %[rsp]
            : [rsp] "=r" (-> u64),
        );

        while (try memory_map.next()) |entry| {
            if (entry.region.address.value() < rsp and rsp < entry.region.address.offset(entry.region.size).value()) {
                const rsp_region_physical_address = entry.region.address;
                const rsp_region_virtual_address = rsp_region_physical_address.toIdentityMappedVirtualAddress();
                if (entry.region.size == 0) return Error.region_empty;
                try minimal_paging.map(rsp_region_physical_address, rsp_region_virtual_address, entry.region.size, .{ .write = true, .execute = false }, page_allocator);
                log.debug("Ended ensuring stack is mapped", .{});
                return;
            }
        }

        return Error.map_failed;
    }
};

pub const std_options = struct {
    pub const log_level = lib.std.log.Level.debug;

    pub fn logFn(comptime level: lib.std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
        const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
        switch (lib.cpu.arch) {
            .x86_64 => {
                // if (maybe_bootloader_information) |bootloader_information| {
                //     if (@enumToInt(bootloader_information.stage) < @enumToInt(bootloader.Stage.only_graphics)) {
                //         var buffer: [4096]u8 = undefined;
                //         const formatted_buffer = lib.std.fmt.bufPrint(buffer[0..], prefix ++ format ++ "\r\n", args) catch unreachable;
                //
                //         for (formatted_buffer) |c| {
                //             const fake_c = [2]u16{ c, 0 };
                //             _ = UEFI.get_system_table().con_out.?.outputString(@ptrCast(*const [1:0]u16, &fake_c));
                //         }
                //     } else {
                //         draw_writer.print(prefix ++ format ++ "\n", args) catch unreachable;
                //     }
                // }

                writer.print(prefix ++ format ++ "\n", args) catch {};
            },
            .aarch64, .riscv64 => {},
            else => @compileError("Unsupported CPU architecture"),
        }
    }
};

const practical_memory_map_descriptor_size = 0x30;
const practical_memory_map_descriptor_count = 256;

const Error = error{
    boot_services_not_found,
    con_out_not_found,
    rsdp_not_found,
    file_descriptor_buffer_not_big_enough,
    map_failed,
    region_empty,
};

const Initialization = struct {
    filesystem: Filesystem,
    memory_map: MemoryMap,
    framebuffer: Framebuffer,
    virtual_address_space: VirtualAddressSpace,
    architecture: switch (lib.cpu.arch) {
        .x86_64 => struct {
            rsdp: *ACPI.RSDP.Descriptor1,
        },
        else => @compileError("Architecture not supported"),
    },
    system_table: *SystemTable,

    fn initialize(init: *Initialization) !void {
        const system_table = UEFI.getSystemTable();
        const handle = UEFI.getHandle();
        const boot_services = system_table.boot_services orelse return Error.boot_services_not_found;
        const out = system_table.con_out orelse return Error.con_out_not_found;
        try UEFI.Try(out.reset(true));
        try UEFI.Try(out.clearScreen());

        init.* = .{
            .filesystem = .{
                .boot_services = boot_services,
                .handle = handle,
                .root = undefined,
            },
            .memory_map = .{
                .boot_services = boot_services,
                .handle = handle,
                .key = 0,
                .descriptor_size = 0,
                .descriptor_version = 0,
            },
            .framebuffer = .{
                .boot_services = boot_services,
            },
            .virtual_address_space = undefined,
            .architecture = switch (lib.cpu.arch) {
                .x86_64 => .{
                    .rsdp = blk: {
                        const configuration_tables = system_table.configuration_table[0..system_table.number_of_table_entries];

                        const rsdp = for (configuration_tables) |configuration_table| {
                            if (configuration_table.vendor_guid.eql(ConfigurationTable.acpi_20_table_guid)) {
                                break @ptrCast(*ACPI.RSDP.Descriptor1, @alignCast(@alignOf(ACPI.RSDP.Descriptor1), configuration_table.vendor_table));
                            }
                        } else return Error.rsdp_not_found;

                        break :blk rsdp;
                    },
                },
                else => @compileError("Architecture not supported"),
            },
            .system_table = system_table,
        };
    }

    pub fn getRSDPAddress(init: *Initialization) u32 {
        return switch (lib.cpu.arch) {
            .x86_64 => @intCast(u32, @ptrToInt(init.architecture.rsdp)),
            else => @compileError("Architecture not supported"),
        };
    }

    pub fn getCPUCount(init: *Initialization) !u32 {
        return switch (lib.cpu.arch) {
            .x86_64 => blk: {
                const madt_header = try init.architecture.rsdp.findTable(.APIC);
                const madt = @ptrCast(*align(1) const ACPI.MADT, madt_header);
                break :blk madt.getCPUCount();
            },
            else => @compileError("Architecture not supported"),
        };
    }
};

var initialization: Initialization = undefined;

pub fn main() noreturn {
    initialization.initialize() catch |err| {
        UEFI.panic("Error happened while UEFI early initialization: {}", .{err});
    };

    bootloader.Information.initialize(&initialization, .rise, .uefi) catch |err| {
        UEFI.panic("Error happened in bootloader initialization: {}", .{err});
    };
}
