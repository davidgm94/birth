const lib = @import("lib");
const Allocator = lib.Allocator;
const log = lib.log;
const privileged = @import("privileged");
const ACPI = privileged.ACPI;
const MemoryManager = privileged.MemoryManager;
const PhysicalHeap = privileged.PhyicalHeap;
const writer = privileged.writer;

const GDT = privileged.arch.x86_64.GDT;
const Mapping = privileged.Mapping;
const PhysicalAddress = privileged.PhysicalAddress;
const VirtualAddress = privileged.VirtualAddress;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const VirtualMemoryRegion = privileged.VirtualMemoryRegion;

const bootloader = @import("bootloader");
const BIOS = bootloader.BIOS;

extern const loader_start: u8;
extern const loader_end: u8;

// var files: [16]File = undefined;
// var file_count: u8 = 0;
//
// const File = struct {
//     path: []const u8,
//     content: []const u8,
//     type: bootloader.File.Type,
// };

const FATAllocator = extern struct {
    buffer: [0x2000]u8 = undefined,
    allocated: usize = 0,
    allocator: Allocator = .{
        .callbacks = .{
            .allocate = allocate,
        },
    },

    pub fn allocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
        const fat = @fieldParentPtr(FATAllocator, "allocator", allocator);
        const aligned_allocated = lib.alignForward(fat.allocated, @intCast(usize, alignment));
        if (aligned_allocated + size > fat.buffer.len) @panic("no alloc");
        fat.allocated = aligned_allocated;
        const result = Allocator.Allocate.Result{
            .address = @ptrToInt(&fat.buffer) + fat.allocated,
            .size = size,
        };
        fat.allocated += @intCast(usize, size);
        return result;
    }
};

pub const std_options = struct {
    pub const log_level = lib.std.log.Level.debug;

    pub fn logFn(comptime level: lib.std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        _ = level;
        writer.writeByte('[') catch unreachable;
        writer.writeAll(@tagName(scope)) catch unreachable;
        writer.writeAll("] ") catch unreachable;
        lib.format(writer, format, args) catch unreachable;
        writer.writeByte('\n') catch unreachable;
    }
};

pub fn panic(message: []const u8, _: ?*lib.StackTrace, _: ?usize) noreturn {
    privileged.arch.disableInterrupts();
    writer.writeAll("[PANIC] ") catch unreachable;
    writer.writeAll(message) catch unreachable;
    writer.writeByte('\n') catch unreachable;

    if (lib.is_test) {
        privileged.exitFromQEMU(.failure);
    } else {
        privileged.arch.stopCPU();
    }
}

const Filesystem = extern struct {
    fat_allocator: FATAllocator = .{},
    fat_cache: lib.Filesystem.FAT32.Cache,
    disk: BIOS.Disk = .{
        .disk = .{
            // TODO:
            .disk_size = 64 * 1024 * 1024,
            .sector_size = 0x200,
            .callbacks = .{
                .read = BIOS.Disk.read,
                .write = BIOS.Disk.write,
            },
            .type = .bios,
        },
    },
    file_parser: bootloader.File.Parser,
    file_buffer: [512]u8,
    cache_index: usize = 0,

    fn initialize(context: ?*anyopaque) anyerror!void {
        const filesystem = @ptrCast(*Filesystem, @alignCast(@alignOf(Filesystem), context));
        const gpt_cache = try lib.PartitionTable.GPT.Partition.Cache.fromPartitionIndex(&filesystem.disk.disk, 0, &filesystem.fat_allocator.allocator);
        filesystem.fat_cache = try lib.Filesystem.FAT32.Cache.fromGPTPartitionCache(&filesystem.fat_allocator.allocator, gpt_cache);
        const rise_files_file = try filesystem.readFile("/files", &filesystem.file_buffer);
        filesystem.cache_index = filesystem.fat_allocator.allocated;
        filesystem.file_parser = bootloader.File.Parser.init(rise_files_file);
    }

    fn deinitialize(context: ?*anyopaque) anyerror!void {
        const filesystem = @ptrCast(*Filesystem, @alignCast(@alignOf(Filesystem), context));
        filesystem.fat_allocator.allocated = filesystem.cache_index;
        filesystem.file_parser.reset();
    }

    fn getNextFileDescriptor(context: ?*anyopaque) anyerror!?bootloader.Information.Initialization.Filesystem.Descriptor {
        const filesystem = @ptrCast(*Filesystem, @alignCast(@alignOf(Filesystem), context));
        if (try filesystem.file_parser.next()) |next| {
            const file_path = next.guest;
            return .{
                .path = file_path,
                .size = try filesystem.fat_cache.getFileSize(file_path),
                .type = next.type,
            };
        } else return null;
    }

    fn readFile(filesystem: *Filesystem, file_path: []const u8, file_buffer: []u8) anyerror![]const u8 {
        const file = try filesystem.fat_cache.readFileToBuffer(file_path, file_buffer);
        return file;
    }

    fn readFileCallback(context: ?*anyopaque, file_path: []const u8, file_buffer: []u8) anyerror![]const u8 {
        const filesystem = @ptrCast(*Filesystem, @alignCast(@alignOf(Filesystem), context));
        return try filesystem.readFile(file_path, file_buffer);
    }

    fn getFileSize(context: ?*anyopaque, file_path: []const u8) anyerror!u32 {
        const filesystem = @ptrCast(*Filesystem, @alignCast(@alignOf(Filesystem), context));
        const file_size = try filesystem.fat_cache.getFileSize(file_path);
        return file_size;
    }

    fn getCacheIndex(context: ?*anyopaque) u32 {
        const filesystem = @ptrCast(*Filesystem, @alignCast(@alignOf(Filesystem), context));
        return filesystem.fat_allocator.allocated;
    }

    fn setCacheIndex(context: ?*anyopaque, cache_index: u32) void {
        const filesystem = @ptrCast(*Filesystem, @alignCast(@alignOf(Filesystem), context));
        filesystem.fat_allocator.allocated = cache_index;
    }
};

const MemoryMap = extern struct {
    iterator: BIOS.E820Iterator,

    fn initialize(context: ?*anyopaque) anyerror!void {
        const mmap = @ptrCast(*MemoryMap, @alignCast(@alignOf(MemoryMap), context));
        mmap.iterator = .{};
    }
    fn deinitialize(context: ?*anyopaque) anyerror!void {
        const mmap = @ptrCast(*MemoryMap, @alignCast(@alignOf(MemoryMap), context));
        mmap.iterator = .{};
    }

    fn getMemoryMapEntryCount(context: ?*anyopaque) anyerror!u32 {
        _ = context;
        return BIOS.getMemoryMapEntryCount();
    }

    fn next(context: ?*anyopaque) anyerror!?bootloader.MemoryMapEntry {
        const mmap = @ptrCast(*MemoryMap, @alignCast(@alignOf(MemoryMap), context));

        if (mmap.iterator.next()) |bios_entry| {
            return .{
                .region = bios_entry.region,
                .type = switch (bios_entry.type) {
                    .usable => if (bios_entry.isUsable()) .usable else .reserved,
                    .bad_memory => .bad_memory,
                    else => .reserved,
                },
            };
        }

        return null;
    }
};

const Framebuffer = extern struct {
    fn initialize(context: ?*anyopaque) anyerror!bootloader.Framebuffer {
        _ = context;
        var vbe_info: BIOS.VBE.Information = undefined;

        const edid_info = BIOS.VBE.getEDIDInfo() catch @panic("No EDID");
        const edid_width = edid_info.getWidth();
        const edid_height = edid_info.getHeight();
        const edid_bpp = 32;
        const preferred_resolution = if (edid_width != 0 and edid_height != 0) .{ .x = edid_width, .y = edid_height } else @panic("No EDID");
        _ = preferred_resolution;
        BIOS.VBE.getControllerInformation(&vbe_info) catch @panic("No VBE information");

        if (!lib.equal(u8, &vbe_info.signature, "VESA")) {
            @panic("VESA signature");
        }

        if (vbe_info.version_major != 3 and vbe_info.version_minor != 0) {
            @panic("VESA version");
        }

        const edid_video_mode = vbe_info.getVideoMode(BIOS.VBE.Mode.defaultIsValid, edid_width, edid_height, edid_bpp) orelse @panic("No video mode");
        const framebuffer_region = PhysicalMemoryRegion.new(PhysicalAddress.new(edid_video_mode.framebuffer_address), edid_video_mode.linear_bytes_per_scanline * edid_video_mode.resolution_y);
        const framebuffer = .{
            .address = framebuffer_region.address.value(),
            .pitch = edid_video_mode.linear_bytes_per_scanline,
            .width = edid_video_mode.resolution_x,
            .height = edid_video_mode.resolution_y,
            .bpp = edid_video_mode.bpp,
            .red_mask = .{
                .shift = edid_video_mode.linear_red_mask_shift,
                .size = edid_video_mode.linear_red_mask_size,
            },
            .green_mask = .{
                .shift = edid_video_mode.linear_green_mask_shift,
                .size = edid_video_mode.linear_green_mask_size,
            },
            .blue_mask = .{
                .shift = edid_video_mode.linear_blue_mask_shift,
                .size = edid_video_mode.linear_blue_mask_size,
            },
            // TODO:
            .memory_model = 0x06,
        };

        return framebuffer;
    }
};

const VirtualAddressSpace = extern struct {
    fn ensureLoaderIsMapped(context: ?*anyopaque, paging: privileged.arch.paging.Specific, page_allocator_interface: privileged.PageAllocatorInterface, bootloader_information: *bootloader.Information) anyerror!void {
        _ = bootloader_information;
        _ = context;
        const loader_physical_start = PhysicalAddress.new(lib.alignBackward(@ptrToInt(&loader_start), lib.arch.valid_page_sizes[0]));
        const loader_size = lib.alignForwardGeneric(u64, @ptrToInt(&loader_end) - @ptrToInt(&loader_start) + @ptrToInt(&loader_start) - loader_physical_start.value(), lib.arch.valid_page_sizes[0]);
        try paging.map(loader_physical_start, loader_physical_start.toIdentityMappedVirtualAddress(), lib.alignForwardGeneric(u64, loader_size, lib.arch.valid_page_sizes[0]), .{ .write = true, .execute = true }, page_allocator_interface);
    }

    fn ensureStackIsMapped(context: ?*anyopaque, paging: privileged.arch.paging.Specific, page_allocator_interface: privileged.PageAllocatorInterface) anyerror!void {
        _ = context;
        const loader_stack_size = BIOS.stack_size;
        const loader_stack = PhysicalAddress.new(lib.alignForwardGeneric(u32, BIOS.stack_top, lib.arch.valid_page_sizes[0]) - loader_stack_size);
        paging.map(loader_stack, loader_stack.toIdentityMappedVirtualAddress(), loader_stack_size, .{ .write = true, .execute = false }, page_allocator_interface) catch @panic("Mapping of loader stack failed");
    }
};

export fn entryPoint() callconv(.C) noreturn {
    main() catch |err| {
        @panic(@errorName(err));
    };
}

var fs = Filesystem{
    .fat_cache = undefined,
    .file_parser = undefined,
    .file_buffer = undefined,
};

var memory_map = MemoryMap{
    .iterator = .{},
};

fn main() !noreturn {
    BIOS.A20Enable() catch @panic("can't enable a20");

    const rsdp_address = BIOS.findRSDP() orelse @panic("Can't find RSDP");
    const rsdp = @intToPtr(*ACPI.RSDP.Descriptor1, rsdp_address);
    const bootloader_information = try bootloader.Information.initialize(.{
        .context = &fs,
        .initialize = Filesystem.initialize,
        .deinitialize = Filesystem.deinitialize,
        .get_next_file_descriptor = Filesystem.getNextFileDescriptor,
        .read_file = Filesystem.readFileCallback,
    }, .{
        .context = &memory_map,
        .initialize = MemoryMap.initialize,
        .deinitialize = MemoryMap.deinitialize,
        .get_memory_map_entry_count = MemoryMap.getMemoryMapEntryCount,
        .next = MemoryMap.next,
        .get_host_region = null,
    }, .{
        .context = null,
        .initialize = Framebuffer.initialize,
    }, .{
        .context = null,
        .ensure_loader_is_mapped = VirtualAddressSpace.ensureLoaderIsMapped,
        .ensure_stack_is_mapped = VirtualAddressSpace.ensureStackIsMapped,
    }, rsdp, .rise, .bios);
    _ = bootloader_information;

    @panic("loader not found");
}
