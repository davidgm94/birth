const lib = @import("lib");
const Allocator = lib.Allocator;
const log = lib.log;
const privileged = @import("privileged");
const ACPI = privileged.ACPI;
const MemoryMap = privileged.MemoryMap;
const MemoryManager = privileged.MemoryManager;
const PhysicalHeap = privileged.PhyicalHeap;
const writer = privileged.writer;

const x86_64 = privileged.arch.x86_64;
const GDT = x86_64.GDT;
const PhysicalAddress = x86_64.PhysicalAddress;
const VirtualAddress = x86_64.VirtualAddress;
const PhysicalMemoryRegion = x86_64.PhysicalMemoryRegion;
const VirtualMemoryRegion = x86_64.VirtualMemoryRegion;
const VirtualAddressSpace = x86_64.VirtualAddressSpace;

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

var fat_allocator = FATAllocator{};

export fn entryPoint() callconv(.C) noreturn {
    BIOS.A20Enable() catch @panic("can't enable a20");
    lib.log.debug("Loader start: 0x{x}. Loader end: 0x{x}", .{ @ptrToInt(&loader_start), @ptrToInt(&loader_end) });
    writer.writeAll("[STAGE 1] Initializing\n") catch unreachable;

    var iterator = BIOS.E820Iterator{};
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

    const rsdp_address = BIOS.findRSDP() orelse @panic("Can't find RSDP");
    const rsdp = @intToPtr(*ACPI.RSDP.Descriptor1, rsdp_address);
    const madt_header = rsdp.findTable(.APIC) orelse @panic("Can't find MADT");
    const madt = @fieldParentPtr(ACPI.MADT, "header", madt_header);
    const cpu_count = madt.getCPUCount();

    const bsp_lapic_id = @intToPtr(*volatile u32, 0x0FEE00020).*;
    const memory_map_entry_count = BIOS.getMemoryMapEntryCount();

    var bios_disk = BIOS.Disk{
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
    };

    const gpt_cache = lib.PartitionTable.GPT.Partition.Cache.fromPartitionIndex(&bios_disk.disk, 0, &fat_allocator.allocator) catch @panic("can't load gpt cache");
    var fat_cache = lib.Filesystem.FAT32.Cache.fromGPTPartitionCache(&fat_allocator.allocator, gpt_cache) catch @panic("can't load fat cache");
    const rise_files_file = fat_cache.readFile(&fat_allocator.allocator, "/files") catch @panic("cant load json from disk");
    const cache_allocated = fat_allocator.allocated;
    var file_parser = bootloader.File.Parser.init(rise_files_file);
    var total_file_size: usize = 0;
    var total_aligned_file_size: usize = 0;
    var total_file_name_size: usize = 0;
    var file_count: usize = 0;
    const file_alignment = 0x200;
    const cpu_driver_name = blk: {
        var maybe_cpu_driver_name: ?[]const u8 = null;
        while (file_parser.next() catch {
            @panic("Error while parsing");
        }) |file_descriptor| {
            const file_name = file_descriptor.guest;
            if (file_descriptor.type == .cpu_driver) {
                if (maybe_cpu_driver_name != null) @panic("Two cpu drivers");
                maybe_cpu_driver_name = file_name;
            }

            const file_size = fat_cache.getFileSize(file_name) catch @panic("cant'get file size");
            total_file_size += file_size;
            total_aligned_file_size += lib.alignForward(file_size, file_alignment);
            total_file_name_size += file_name.len;

            file_count += 1;
        }

        break :blk maybe_cpu_driver_name orelse @panic("No CPU driver specified in the configuration");
    };

    file_parser = bootloader.File.Parser.init(rise_files_file);
    fat_allocator.allocated = cache_allocated;

    const length_size_tuples = bootloader.LengthSizeTuples.new(.{
        .bootloader_information = .{
            .length = 1,
            .alignment = @alignOf(bootloader.Information),
        },
        .file_names = .{
            .length = total_file_name_size,
            .alignment = 1,
        },
        .files = .{
            .length = file_count,
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
            .alignment = lib.max(8, @alignOf(bootloader.Information.SMP.Information)),
        },
        .file_contents = .{
            .length = total_aligned_file_size,
            .alignment = file_alignment,
        },
    });

    const bootloader_information_address = while (iterator.next()) |entry| {
        if (entry.descriptor.isUsable() and entry.descriptor.region.size > length_size_tuples.getAlignedTotalSize() and !entry.descriptor.region.overlaps(framebuffer_region)) {
            const bootloader_information_region = entry.descriptor.region.takeSlice(@sizeOf(bootloader.Information));
            const bootloader_information = bootloader_information_region.address.toIdentityMappedVirtualAddress().access(*bootloader.Information);

            bootloader_information.* = .{
                .protocol = .bios,
                .bootloader = .rise,
                .version = .{ .major = 0, .minor = 1, .patch = 0 },
                .total_size = length_size_tuples.total_size,
                .entry_point = 0,
                .higher_half = lib.config.cpu_driver_higher_half_address,
                .stage = .early,
                .configuration = .{
                    .memory_map_diff = 0,
                },
                .framebuffer = .{
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
                },
                .draw_context = .{},
                .font = undefined,
                .cpu_driver_mappings = .{},
                .smp = .{
                    .cpu_count = cpu_count,
                    .bsp_lapic_id = bsp_lapic_id,
                },
                .slices = length_size_tuples.createSlices(),
                .architecture = .{
                    .rsdp_address = rsdp_address,
                },
            };

            const page_counters = bootloader_information.getSlice(.page_counters);
            for (page_counters) |*page_counter| {
                page_counter.* = 0;
            }

            page_counters[entry.index] = bootloader_information.getAlignedTotalSize() >> lib.arch.page_shifter(lib.arch.valid_page_sizes[0]);

            const memory_map_entries = bootloader_information.getSlice(.memory_map_entries);
            BIOS.fetchMemoryEntries(memory_map_entries);

            break bootloader_information_region.address;
        }
    } else {
        @panic("No memory map");
    };

    const bootloader_information = bootloader_information_address.toIdentityMappedVirtualAddress().access(*bootloader.Information);

    // fat_cache.allocator = allocator;

    // Read files
    {
        const file_content_buffer = bootloader_information.getSlice(.file_contents);
        const file_name_buffer = bootloader_information.getSlice(.file_names);
        const file_slice = bootloader_information.getSlice(.files);

        var file_content_offset: usize = 0;
        var file_name_offset: usize = 0;
        var file_index: usize = 0;

        while (file_parser.next() catch @panic("Cant' parse files file")) |file_descriptor| {
            const file_name = file_descriptor.guest;
            lib.copy(u8, file_name_buffer[file_name_offset .. file_content_offset + file_name.len], file_name);
            const file_size = fat_cache.getFileSize(file_name) catch @panic("can't get file size");
            const aligned_file_size = lib.alignForward(file_size, file_alignment);
            const file_buffer = file_content_buffer[file_content_offset .. file_content_offset + aligned_file_size];
            _ = fat_cache.readFileToBuffer(file_name, file_buffer) catch @panic("cant load json from disk");

            file_slice[file_index] = .{
                .content_offset = file_content_offset,
                .content_size = file_size,
                .path_offset = file_name_offset,
                .path_size = file_name.len,
                .type = file_descriptor.type,
            };

            file_content_offset += aligned_file_size;
            file_name_offset += file_name.len;
            file_index += 1;
        }

        if (file_content_offset != file_content_buffer.len) @panic("File content slice size mismatch");
        if (file_name_offset != file_name_buffer.len) @panic("File name slice size mismatch");
        if (file_index != file_count) @panic("File count mismatch");
    }

    const minimal_paging = bootloader_information.initializeVirtualAddressSpace();

    const entries = bootloader_information.getMemoryMapEntries();
    for (entries) |entry| {
        if (entry.type == .usable) {
            // bootloader_information.virtual_address_space.map entry.region.address, entry.region.address.toIdentityMappedVirtualAddress(), lib.alignForwardGeneric(u64, entry.region.size, lib.arch.valid_page_sizes[0]), .{ .write = true, .execute = false }) catch @panic("Mapping of memory map entry failed (identity)");
            minimal_paging.map(entry.region.address, entry.region.address.toHigherHalfVirtualAddress(), lib.alignForwardGeneric(u64, entry.region.size, lib.arch.valid_page_sizes[0]), .{ .write = true, .execute = false }, .bootloader) catch @panic("Mapping memory entry (HH)"); //catch |err| privileged.panic("Mapping of memory map entry failed (higher half): {}", .{err});
        }
    }

    minimal_paging.map(bootloader_information_address, bootloader_information_address.toIdentityMappedVirtualAddress(), bootloader_information.getAlignedTotalSize(), .{ .write = true, .execute = false }, .bootloader) catch @panic("bootloader information mapping"); //|err| // privileged.panic("Bootloader information mapping failed: {}", .{err});

    lib.log.debug("Loader", .{});

    const loader_physical_start = PhysicalAddress.new(lib.alignBackward(@ptrToInt(&loader_start), lib.arch.valid_page_sizes[0]));
    const loader_size = lib.alignForwardGeneric(u64, @ptrToInt(&loader_end) - @ptrToInt(&loader_start) + @ptrToInt(&loader_start) - loader_physical_start.value(), lib.arch.valid_page_sizes[0]);
    minimal_paging.map(loader_physical_start, loader_physical_start.toIdentityMappedVirtualAddress(), lib.alignForwardGeneric(u64, loader_size, lib.arch.valid_page_sizes[0]), .{ .write = true, .execute = true }, .bootloader) catch |err| {
        log.debug("Error: {}", .{err});
        @panic("Mapping of BIOS loader failed");
    };
    lib.log.debug("Framebuffer", .{});
    const framebuffer_physical_address = PhysicalAddress.new(bootloader_information.framebuffer.address);
    minimal_paging.map(framebuffer_physical_address, framebuffer_physical_address.toHigherHalfVirtualAddress(), lib.alignForwardGeneric(u64, bootloader_information.framebuffer.getSize(), lib.arch.valid_page_sizes[0]), .{ .write = true, .execute = false }, .bootloader) catch @panic("can't map framebuffer");
    bootloader_information.framebuffer.address = framebuffer_physical_address.toHigherHalfVirtualAddress().value();

    // Map more than necessary
    //
    // Dirty trick
    lib.log.debug("Loader stack", .{});
    const loader_stack_size = BIOS.stack_size;
    const loader_stack = PhysicalAddress.new(lib.alignForwardGeneric(u32, BIOS.stack_top, lib.arch.valid_page_sizes[0]) - loader_stack_size);
    minimal_paging.map(loader_stack, loader_stack.toIdentityMappedVirtualAddress(), loader_stack_size, .{ .write = true, .execute = false }, .bootloader) catch @panic("Mapping of loader stack failed");

    // TODO:
    for (bootloader_information.getSlice(.files)) |file_descriptor| {
        if (lib.equal(u8, file_descriptor.getPath(bootloader_information), cpu_driver_name)) {
            const file_content = file_descriptor.getContent(bootloader_information);
            var parser = lib.ELF(64).Parser.init(file_content) catch @panic("Can't parser ELF");

            const program_headers = parser.getProgramHeaders();
            for (program_headers) |*ph| {
                switch (ph.type) {
                    .load => {
                        if (ph.size_in_memory == 0) continue;

                        if (!ph.flags.readable) {
                            @panic("ELF program segment is marked as non-readable");
                        }

                        if (ph.size_in_file != ph.size_in_memory) {
                            @panic("ELF program segment file size is smaller than memory size");
                        }

                        const aligned_size = lib.alignForwardGeneric(u64, ph.size_in_memory, lib.arch.valid_page_sizes[0]);
                        const physical_allocation = bootloader_information.allocatePages(aligned_size, lib.arch.valid_page_sizes[0]) catch @panic("WTDASD");
                        const physical_address = physical_allocation.address;
                        const virtual_address = VirtualAddress.new(ph.virtual_address);
                        const flags = VirtualAddressSpace.Flags{ .write = ph.flags.writable, .execute = ph.flags.executable };

                        switch (ph.flags.executable) {
                            true => switch (ph.flags.writable) {
                                true => @panic("Text section is not supposed to be writable"),
                                false => {
                                    bootloader_information.cpu_driver_mappings.text = .{
                                        .physical = physical_address,
                                        .virtual = virtual_address,
                                        .size = ph.size_in_memory,
                                        .flags = flags,
                                    };
                                },
                            },
                            false => switch (ph.flags.writable) {
                                true => bootloader_information.cpu_driver_mappings.data = .{
                                    .physical = physical_address,
                                    .virtual = virtual_address,
                                    .size = ph.size_in_memory,
                                    .flags = flags,
                                },
                                false => bootloader_information.cpu_driver_mappings.rodata = .{
                                    .physical = physical_address,
                                    .virtual = virtual_address,
                                    .size = ph.size_in_memory,
                                    .flags = flags,
                                },
                            },
                        }

                        log.debug("Started mapping kernel section", .{});
                        minimal_paging.map(physical_address, virtual_address, aligned_size, flags, .bootloader) catch {
                            @panic("Mapping of section failed");
                        };
                        log.debug("Ended mapping kernel section", .{});

                        const dst_slice = physical_address.toIdentityMappedVirtualAddress().access([*]u8)[0..lib.safeArchitectureCast(ph.size_in_memory)];
                        const src_slice = file_content[lib.safeArchitectureCast(ph.offset)..][0..lib.safeArchitectureCast(ph.size_in_file)];
                        log.debug("Src slice: [0x{x}, 0x{x}]. Dst slice: [0x{x}, 0x{x}]", .{ @ptrToInt(src_slice.ptr), @ptrToInt(src_slice.ptr) + src_slice.len, @ptrToInt(dst_slice.ptr), @ptrToInt(dst_slice.ptr) + dst_slice.len });
                        if (!(dst_slice.len >= src_slice.len)) {
                            @panic("bios: segment allocated memory must be equal or greater than especified");
                        }

                        lib.copy(u8, dst_slice, src_slice);
                    },
                    else => {
                        //log.warn("Unhandled PH {s}", .{@tagName(ph.type)});
                    },
                }
            }

            // INFO: The bootloader information struct is not actually mapped because it was mapped previously when mapping all usable memory

            //bootloader_information.initializeSMP(madt);

            bootloader_information.entry_point = parser.getEntryPoint();

            //bootloader_information.virtual_address_space.validate() catch @panic("Validation failed");

            writer.writeAll("[STAGE 1] Trying to jump to CPU driver...\n") catch unreachable;

            if (bootloader_information.entry_point != 0) {
                bootloader.arch.x86_64.jumpToKernel(bootloader_information, minimal_paging);
            }
        }
    }

    // for (files) |file| {
    //     if (lib.equal(u8, file.path, cpu_driver_name)) {
    // }

    @panic("loader not found");
}

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
