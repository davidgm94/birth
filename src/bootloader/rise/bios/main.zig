const lib = @import("lib");
const Allocator = lib.Allocator;
const assert = lib.assert;
const log = lib.log;
const privileged = @import("privileged");
const ACPI = privileged.ACPI;
const MemoryManager = privileged.MemoryManager;
const PhysicalHeap = privileged.PhyicalHeap;
const writer = privileged.writer;

const stopCPU = privileged.arch.stopCPU;
const GDT = privileged.arch.x86_64.GDT;
const Mapping = privileged.Mapping;
const PageAllocator = privileged.PageAllocator;
const PhysicalAddress = lib.PhysicalAddress;
const VirtualAddress = lib.VirtualAddress;
const PhysicalMemoryRegion = lib.PhysicalMemoryRegion;
const VirtualMemoryRegion = lib.VirtualMemoryRegion;

const bootloader = @import("bootloader");
const bios = @import("bios");

extern const loader_start: u8;
extern const loader_end: u8;

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
        const aligned_allocated = lib.alignForward(usize, fat.allocated, @as(usize, @intCast(alignment)));
        if (aligned_allocated + size > fat.buffer.len) @panic("no alloc");
        fat.allocated = aligned_allocated;
        const result = Allocator.Allocate.Result{
            .address = @intFromPtr(&fat.buffer) + fat.allocated,
            .size = size,
        };
        fat.allocated += @as(usize, @intCast(size));
        return result;
    }
};

pub const std_options = struct {
    pub const log_level = lib.std.log.Level.debug;

    pub fn logFn(comptime level: lib.std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        _ = args;
        _ = format;
        _ = scope;
        _ = level;
        // _ = level;
        // writer.writeByte('[') catch stopCPU();
        // writer.writeAll(@tagName(scope)) catch stopCPU();
        // writer.writeAll("] ") catch stopCPU();
        // lib.format(writer, format, args) catch stopCPU();
        // writer.writeByte('\n') catch stopCPU();
    }
};

pub fn panic(message: []const u8, _: ?*lib.StackTrace, _: ?usize) noreturn {
    privileged.arch.disableInterrupts();
    writer.writeAll("[PANIC] ") catch stopCPU();
    writer.writeAll(message) catch stopCPU();
    writer.writeByte('\n') catch stopCPU();

    privileged.shutdown(.failure);
}

const Filesystem = extern struct {
    fat_allocator: FATAllocator = .{},
    fat_cache: lib.Filesystem.FAT32.Cache,
    disk: bios.Disk = .{},
    cache_index: usize = 0,

    pub fn deinitialize(filesystem: *Filesystem) !void {
        filesystem.fat_allocator.allocated = filesystem.cache_index;
    }

    pub fn readFile(filesystem: *Filesystem, file_path: []const u8, file_buffer: []u8) ![]const u8 {
        log.debug("File {s} read started", .{file_path});
        assert(filesystem.fat_allocator.allocated <= filesystem.fat_allocator.buffer.len);
        const file = try filesystem.fat_cache.readFileToBuffer(file_path, file_buffer);
        log.debug("File read succeeded", .{});
        return file;
    }

    pub fn sneakFile(filesystem: *Filesystem, file_path: []const u8, size: usize) ![]const u8 {
        log.debug("File {s} read started", .{file_path});
        const file = try filesystem.fat_cache.readFileToCache(file_path, size);
        log.debug("File read succeeded", .{});
        return file;
    }

    pub fn getFileSize(filesystem: *Filesystem, file_path: []const u8) !u32 {
        const file_size = try filesystem.fat_cache.getFileSize(file_path);
        filesystem.fat_allocator.allocated = filesystem.cache_index;
        return file_size;
    }

    pub fn getSectorSize(filesystem: *Filesystem) u16 {
        return filesystem.disk.disk.sector_size;
    }
};

const MemoryMap = extern struct {
    iterator: bios.E820Iterator,
    entry_count: u32,

    pub fn getEntryCount(memory_map: *const MemoryMap) u32 {
        return memory_map.entry_count;
    }

    pub fn next(memory_map: *MemoryMap) !?bootloader.MemoryMapEntry {
        if (memory_map.iterator.next()) |bios_entry| {
            return .{
                .region = bios_entry.toPhysicalMemoryRegion(),
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

const Initialization = struct {
    filesystem: Filesystem,
    memory_map: MemoryMap,
    framebuffer: bootloader.Framebuffer,
    architecture: switch (lib.cpu.arch) {
        .x86, .x86_64 => struct {
            rsdp: u32,
        },
        else => @compileError("Architecture not supported"),
    },
    early_initialized: bool = false,
    framebuffer_initialized: bool = false,
    memory_map_initialized: bool = false,
    filesystem_initialized: bool = false,

    pub fn getCPUCount(init: *Initialization) !u32 {
        return switch (lib.cpu.arch) {
            .x86, .x86_64 => blk: {
                const rsdp = @as(*ACPI.RSDP.Descriptor1, @ptrFromInt(init.architecture.rsdp));
                const madt_header = try rsdp.findTable(.APIC);
                const madt = @as(*align(1) const ACPI.MADT, @ptrCast(madt_header));
                break :blk madt.getCPUCount();
            },
            else => @compileError("Architecture not supported"),
        };
    }

    pub fn getRSDPAddress(init: *Initialization) u32 {
        return init.architecture.rsdp;
    }

    pub fn deinitializeMemoryMap(init: *Initialization) !void {
        init.memory_map.iterator = bios.E820Iterator{};
    }

    pub fn ensureLoaderIsMapped(init: *Initialization, paging: privileged.arch.paging.Specific, page_allocator: PageAllocator, bootloader_information: *bootloader.Information) !void {
        _ = init;
        _ = bootloader_information;
        const loader_physical_start = PhysicalAddress.new(lib.alignBackward(usize, @intFromPtr(&loader_start), lib.arch.valid_page_sizes[0]));
        const loader_size = lib.alignForward(u64, @intFromPtr(&loader_end) - @intFromPtr(&loader_start) + @intFromPtr(&loader_start) - loader_physical_start.value(), lib.arch.valid_page_sizes[0]);
        // Not caring about safety here
        try paging.map(loader_physical_start, loader_physical_start.toIdentityMappedVirtualAddress(), lib.alignForward(u64, loader_size, lib.arch.valid_page_sizes[0]), .{ .write = true, .execute = true }, page_allocator);
    }

    pub fn ensureStackIsMapped(init: *Initialization, paging: privileged.arch.paging.Specific, page_allocator: PageAllocator) !void {
        _ = init;
        const loader_stack_size = bios.stack_size;
        const loader_stack = PhysicalAddress.new(lib.alignForward(u32, bios.stack_top, lib.arch.valid_page_sizes[0]) - loader_stack_size);
        try paging.map(loader_stack, loader_stack.toIdentityMappedVirtualAddress(), loader_stack_size, .{ .write = true, .execute = false }, page_allocator);
    }

    pub fn initialize(init: *Initialization) !void {
        // assert(!init.filesystem.initialized);
        // defer init.filesystem.initialized = true;
        init.* = .{
            .filesystem = .{
                .fat_cache = undefined,
            },
            .memory_map = .{
                .iterator = .{},
                .entry_count = bios.getMemoryMapEntryCount(),
            },
            .architecture = switch (lib.cpu.arch) {
                .x86, .x86_64 => .{
                    .rsdp = @intFromPtr(try bios.findRSDP()),
                },
                else => @compileError("Architecture not supported"),
            },
            .framebuffer = blk: {
                var vbe_info: bios.VBE.Information = undefined;

                const edid_info = bios.VBE.getEDIDInfo() catch @panic("No EDID");
                const edid_width = edid_info.getWidth();
                const edid_height = edid_info.getHeight();
                const edid_bpp = 32;
                const preferred_resolution = if (edid_width != 0 and edid_height != 0) .{ .x = edid_width, .y = edid_height } else @panic("No EDID");
                _ = preferred_resolution;
                bios.VBE.getControllerInformation(&vbe_info) catch @panic("No VBE information");

                if (!lib.equal(u8, &vbe_info.signature, "VESA")) {
                    @panic("VESA signature");
                }

                if (vbe_info.version_major != 3 and vbe_info.version_minor != 0) {
                    @panic("VESA version");
                }

                const edid_video_mode = vbe_info.getVideoMode(bios.VBE.Mode.defaultIsValid, edid_width, edid_height, edid_bpp) orelse @panic("No video mode");
                const framebuffer_region = PhysicalMemoryRegion.fromRaw(.{
                    .raw_address = edid_video_mode.framebuffer_address,
                    .size = edid_video_mode.linear_bytes_per_scanline * edid_video_mode.resolution_y,
                });

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
                    .memory_model = 0x06,
                };

                break :blk framebuffer;
            },
        };

        const gpt_cache = try lib.PartitionTable.GPT.Partition.Cache.fromPartitionIndex(&init.filesystem.disk.disk, 0, &init.filesystem.fat_allocator.allocator);
        init.filesystem.fat_cache = try lib.Filesystem.FAT32.Cache.fromGPTPartitionCache(&init.filesystem.fat_allocator.allocator, gpt_cache);
        init.filesystem.cache_index = init.filesystem.fat_allocator.allocated;
        try init.deinitializeMemoryMap();

        init.memory_map_initialized = true;
        init.filesystem_initialized = true;
        init.framebuffer_initialized = true;

        init.early_initialized = true;
    }
};

var initialization: Initialization = undefined;

export fn _start() callconv(.C) noreturn {
    bios.A20Enable() catch @panic("A20 is not enabled");

    initialization.initialize() catch |err| @panic(@errorName(err));
    bootloader.Information.initialize(&initialization, .rise, .bios) catch |err| {
        @panic(@errorName(err));
    };
}
