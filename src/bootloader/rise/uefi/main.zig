const lib = @import("lib");
const config = lib.config;
const Allocator = lib.Allocator;
const ELF = lib.ELF(64);
const log = lib.log.scoped(.UEFI);

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
const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const VirtualAddress = privileged.VirtualAddress;
const VirtualAddressSpace = privileged.VirtualAddressSpace;
const VirtualMemoryRegion = privileged.VirtualMemoryRegion;
pub const writer = privileged.writer;

const CPU = privileged.arch.CPU;
const GDT = privileged.arch.x86_64.GDT;
const paging = privileged.arch.paging;

const Stage = enum {
    boot_services,
    after_boot_services,
    trampoline,
};

pub var framebuffer: bootloader.Framebuffer = undefined;
pub fn panic(message: []const u8, _: ?*lib.StackTrace, _: ?usize) noreturn {
    writer.writeAll("[UEFI] [PANIC] ") catch {};
    writer.writeAll(message) catch {};
    writer.writeAll("\r\n") catch {};

    if (lib.is_test) {
        privileged.exitFromQEMU(.failure);
    } else {
        asm volatile ("cli\nhlt");
        unreachable;
    }
}
pub var draw_writer: bootloader.DrawContext.Writer = undefined;

pub var maybe_bootloader_information: ?*bootloader.Information = null;
pub var boot_services_on = true;

const Filesystem = extern struct {
    boot_services: *UEFI.BootServices,
    handle: UEFI.Handle,
    root: *FileProtocol,

    fn initialize(context: ?*anyopaque) anyerror!void {
        const filesystem = @ptrCast(*Filesystem, @alignCast(@alignOf(Filesystem), context));
        const loaded_image = Protocol.open(LoadedImageProtocol, filesystem.boot_services, filesystem.handle);
        const filesystem_protocol = Protocol.open(SimpleFilesystemProtocol, filesystem.boot_services, loaded_image.device_handle orelse @panic("No device handle"));
        try UEFI.Try(filesystem_protocol.openVolume(&filesystem.root));
    }

    fn deinitialize(context: ?*anyopaque) anyerror!void {
        _ = context;
        // const filesystem = @ptrCast(*Filesystem, @alignCast(@alignOf(Filesystem), context));
        // _ = filesystem;
    }

    fn readFileFast(filesystem: *Filesystem, file_path: []const u8, file_buffer: []u8) anyerror![]const u8 {
        const file = try filesystem.openFile(file_path);
        var size: u64 = file_buffer.len;
        try UEFI.Try(file.handle.read(&size, file_buffer.ptr));
        if (file_buffer.len < size) @panic("readFileFast");
        return file_buffer[0..size];
    }

    const FileDescriptor = struct {
        handle: *FileProtocol,
        path_size: u32,
    };

    fn getFileSize(filesystem: *Filesystem, file_path: []const u8) anyerror!u64 {
        const file = try filesystem.openFile(file_path);
        var file_info_buffer: [@sizeOf(UEFI.FileInfo) + 0x100]u8 align(@alignOf(UEFI.FileInfo)) = undefined;
        var file_info_size = file_info_buffer.len;
        try UEFI.Try(file.handle.getInfo(&UEFI.FileInfo.guid, &file_info_size, &file_info_buffer));
        if (file_info_buffer.len < file_info_size) @panic("getFileSize");
        const file_info = @ptrCast(*UEFI.FileInfo, &file_info_buffer);
        return file_info.file_size;
    }

    fn openFile(filesystem: *Filesystem, file_path: []const u8) anyerror!FileDescriptor {
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

    fn getFileDescriptor(context: ?*anyopaque, file_type: bootloader.File.Type) anyerror!bootloader.Information.Initialization.Filesystem.Descriptor {
        const filesystem = @ptrCast(*Filesystem, @alignCast(@alignOf(Filesystem), context));
        const file_name = @tagName(file_type);
        return .{
            .path = file_name,
            .size = @intCast(u32, try filesystem.getFileSize(file_name)),
            .type = file_type,
        };
    }

    fn readFileCallback(context: ?*anyopaque, file_path: []const u8, file_buffer: []u8) anyerror![]const u8 {
        const filesystem = @ptrCast(*Filesystem, @alignCast(@alignOf(Filesystem), context));
        const file = try filesystem.readFileFast(file_path, file_buffer);
        return file;
    }
};

const MMap = extern struct {
    boot_services: *UEFI.BootServices,
    handle: UEFI.Handle,
    size: usize,
    key: usize,
    descriptor_size: usize,
    descriptor_version: u32,
    buffer: [practical_memory_map_descriptor_size * practical_memory_map_descriptor_count]u8 align(@alignOf(MemoryDescriptor)) = undefined,
    offset: usize = 0,

    fn initialize(context: ?*anyopaque) anyerror!void {
        const mmap = @ptrCast(*MMap, @alignCast(@alignOf(MMap), context));
        _ = mmap.boot_services.getMemoryMap(&mmap.size, null, &mmap.key, &mmap.descriptor_size, &mmap.descriptor_version);
    }

    fn deinitialize(context: ?*anyopaque) anyerror!void {
        const mmap = @ptrCast(*MMap, @alignCast(@alignOf(MMap), context));
        if (boot_services_on) {
            defer boot_services_on = false;

            // Add the region for the bootloader information
            mmap.size += mmap.descriptor_size;
            const expected_memory_map_size = mmap.size;
            const expected_memory_map_descriptor_size = mmap.descriptor_size;
            const expected_memory_map_descriptor_version = mmap.descriptor_version;

            log.debug("Getting memory map before exiting boot services...", .{});

            try UEFI.Try(mmap.boot_services.getMemoryMap(&mmap.size, @ptrCast([*]MemoryDescriptor, &mmap.buffer), &mmap.key, &mmap.descriptor_size, &mmap.descriptor_version));
            if (expected_memory_map_size != mmap.size) {
                log.warn("Old memory map size: {}. New memory map size: {}", .{ expected_memory_map_size, mmap.size });
            }
            if (expected_memory_map_descriptor_size != mmap.descriptor_size) {
                @panic("Descriptor size change");
            }
            if (expected_memory_map_descriptor_version != mmap.descriptor_version) {
                @panic("Descriptor version change");
            }
            const real_memory_map_entry_count = @divExact(mmap.size, mmap.descriptor_size);
            const expected_memory_map_entry_count = @divExact(expected_memory_map_size, expected_memory_map_descriptor_size);
            const diff = @intCast(i16, expected_memory_map_entry_count) - @intCast(i16, real_memory_map_entry_count);
            if (diff < 0) {
                @panic("Memory map entry count diff < 0");
            }

            // bootloader_information.configuration.memory_map_diff = @intCast(u8, diff);

            log.debug("Exiting boot services...", .{});
            try UEFI.Try(mmap.boot_services.exitBootServices(mmap.handle, mmap.key));

            privileged.arch.disableInterrupts();
        }

        mmap.offset = 0;
    }

    fn getMemoryMapEntryCount(context: ?*anyopaque) anyerror!u32 {
        const mmap = @ptrCast(*MMap, @alignCast(@alignOf(MMap), context));
        // Return one more since we are expected to allocate a region for the bootloader information
        return @intCast(u32, @divExact(mmap.size, mmap.descriptor_size) + 1);
    }

    fn next(context: ?*anyopaque) anyerror!?bootloader.MemoryMapEntry {
        const mmap = @ptrCast(*MMap, @alignCast(@alignOf(MMap), context));

        if (mmap.offset < mmap.size) {
            const entry = @ptrCast(*MemoryDescriptor, @alignCast(@alignOf(MemoryDescriptor), mmap.buffer[mmap.offset..].ptr)).*;
            mmap.offset += mmap.descriptor_size;
            const result = bootloader.MemoryMapEntry{
                .region = PhysicalMemoryRegion.new(PhysicalAddress.new(entry.physical_start), entry.number_of_pages << UEFI.page_shifter),
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

    fn getHostRegion(context: ?*anyopaque, length_size_tuples: bootloader.LengthSizeTuples) anyerror!PhysicalMemoryRegion {
        const mmap = @ptrCast(*MMap, @alignCast(@alignOf(MMap), context));
        var memory: []align(UEFI.page_size) u8 = undefined;
        const memory_size = length_size_tuples.getAlignedTotalSize();
        try UEFI.Try(mmap.boot_services.allocatePages(.AllocateAnyPages, .LoaderData, memory_size >> UEFI.page_shifter, &memory.ptr));
        memory.len = memory_size;
        lib.zero(memory);

        return PhysicalMemoryRegion.fromSlice(memory);
    }
};

const Framebuffer = extern struct {
    boot_services: *UEFI.BootServices,

    fn initialize(context: ?*anyopaque) anyerror!bootloader.Framebuffer {
        const fb = @ptrCast(*Framebuffer, @alignCast(@alignOf(Framebuffer), context));
        const gop = try Protocol.locate(UEFI.GraphicsOutputProtocol, fb.boot_services);
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

const VAS = extern struct {
    mmap: *anyopaque,

    fn ensureLoaderIsMapped(context: ?*anyopaque, minimal_paging: paging.Specific, page_allocator: PageAllocator, bootloader_information: *bootloader.Information) anyerror!void {
        const vas = @ptrCast(*VAS, @alignCast(@alignOf(VAS), context));
        // Actually mapping the whole UEFI executable so we don't have random problems with code being dereferenced by the trampoline
        switch (lib.cpu.arch) {
            .x86_64 => {
                {
                    const physical_address = PhysicalAddress.new(@ptrToInt(bootloader_information));
                    const size = bootloader_information.getAlignedTotalSize();
                    // minimal_paging.map(physical_address, physical_address.toIdentityMappedVirtualAddress(), size, .{ .write = true, .execute = false }, page_allocator) catch |err| UEFI.panic("Unable to map bootloader information (identity): {}", .{err});
                    try minimal_paging.map(physical_address, physical_address.toHigherHalfVirtualAddress(), size, .{ .write = true, .execute = false }, page_allocator);
                }
                const trampoline_code_start = @ptrToInt(&bootloader.arch.x86_64.jumpToKernel);

                try MMap.deinitialize(vas.mmap);
                while (try MMap.next(vas.mmap)) |entry| {
                    if (entry.region.address.value() < trampoline_code_start and trampoline_code_start < entry.region.address.offset(entry.region.size).value()) {
                        const code_physical_region = entry.region;
                        const code_virtual_address = code_physical_region.address.toIdentityMappedVirtualAddress();
                        try minimal_paging.map(code_physical_region.address, code_virtual_address, code_physical_region.size, .{ .write = false, .execute = true }, page_allocator);
                        return;
                    }
                }
            },
            .aarch64, .riscv64 => @panic("TODO map trampoline"),
            else => @compileError("Architecture not supported"),
        }

        @panic("ensureLoaderIsMapped failed");
    }

    fn ensureStackIsMapped(context: ?*anyopaque, minimal_paging: paging.Specific, page_allocator: PageAllocator) anyerror!void {
        const vas = @ptrCast(*VAS, @alignCast(@alignOf(VAS), context));
        const rsp = asm volatile (
            \\mov %rsp, %[rsp]
            : [rsp] "=r" (-> u64),
        );
        while (try MMap.next(vas.mmap)) |entry| {
            if (entry.region.address.value() < rsp and rsp < entry.region.address.offset(entry.region.size).value()) {
                const rsp_region_physical_address = entry.region.address;
                const rsp_region_virtual_address = rsp_region_physical_address.toIdentityMappedVirtualAddress();
                if (entry.region.size == 0) @panic("region empty ensureStackIsMapped");
                try minimal_paging.map(rsp_region_physical_address, rsp_region_virtual_address, entry.region.size, .{ .write = true, .execute = false }, page_allocator);
                return;
            }
        }

        @panic("ensureStackIsMapped failed");
    }
};

pub fn main() noreturn {
    const system_table = UEFI.get_system_table();
    const handle = UEFI.get_handle();
    const boot_services = system_table.boot_services orelse @panic("boot services");
    const out = system_table.con_out orelse @panic("con out");
    UEFI.result(@src(), out.reset(true));
    UEFI.result(@src(), out.clearScreen());

    const configuration_tables = system_table.configuration_table[0..system_table.number_of_table_entries];
    const rsdp_physical_address = for (configuration_tables) |configuration_table| {
        if (configuration_table.vendor_guid.eql(ConfigurationTable.acpi_20_table_guid)) {
            break PhysicalAddress.new(@ptrToInt(configuration_table.vendor_table));
        }
    } else @panic("Unable to find RSDP");
    const rsdp_descriptor = rsdp_physical_address.toIdentityMappedVirtualAddress().access(*ACPI.RSDP.Descriptor1);

    var filesystem: Filesystem = .{
        .boot_services = boot_services,
        .handle = handle,
        .root = undefined,
    };
    var mmap: MMap = .{
        .boot_services = boot_services,
        .handle = handle,
        .size = 0,
        .key = 0,
        .descriptor_size = 0,
        .descriptor_version = 0,
    };
    var fb = Framebuffer{
        .boot_services = boot_services,
    };
    var vas = VAS{
        .mmap = &mmap,
    };
    bootloader.Information.initialize(.{
        .context = &filesystem,
        .initialize = Filesystem.initialize,
        .deinitialize = Filesystem.deinitialize,
        .get_file_descriptor = Filesystem.getFileDescriptor,
        .read_file = Filesystem.readFileCallback,
    }, .{
        .context = &mmap,
        .initialize = MMap.initialize,
        .deinitialize = MMap.deinitialize,
        .get_memory_map_entry_count = MMap.getMemoryMapEntryCount,
        .next = MMap.next,
        .get_host_region = MMap.getHostRegion,
    }, .{
        .context = &fb,
        .initialize = Framebuffer.initialize,
    }, .{
        .context = &vas,
        .ensure_loader_is_mapped = VAS.ensureLoaderIsMapped,
        .ensure_stack_is_mapped = VAS.ensureStackIsMapped,
    }, rsdp_descriptor, .rise, .uefi) catch |err| {
        @panic(@errorName(err));
    };
}

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
