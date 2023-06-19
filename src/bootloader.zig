const bootloader = @This();

pub const arch = @import("bootloader/arch.zig");

const lib = @import("lib");
const Allocator = lib.Allocator;
const assert = lib.assert;
//const Allocator = lib.Allocator;
pub const Protocol = lib.Bootloader.Protocol;

const privileged = @import("privileged");
const ACPI = privileged.ACPI;
const CPUPageTables = privileged.arch.CPUPageTables;
const PageAllocator = privileged.PageAllocator;
const PhysicalAddress = lib.PhysicalAddress;
const VirtualAddress = lib.VirtualAddress;
const PhysicalMemoryRegion = lib.PhysicalMemoryRegion;
pub const paging = privileged.arch.paging;

pub const Version = extern struct {
    patch: u8,
    minor: u16,
    major: u8,
};

pub const CompactDate = packed struct(u16) {
    year: u7,
    month: u4,
    day: u5,
};

const file_alignment = lib.arch.valid_page_sizes[0];
const last_struct_offset = @offsetOf(Information, "slices");

pub const Information = extern struct {
    entry_point: u64 align(8),
    higher_half: u64 align(8),
    total_size: u32,
    last_struct_offset: u32 = last_struct_offset,
    version: Version,
    protocol: lib.Bootloader.Protocol,
    bootloader: lib.Bootloader,
    stage: Stage,
    configuration: packed struct(u32) {
        memory_map_diff: u8,
        reserved: u24 = 0,
    },
    cpu_driver_mappings: CPUDriverMappings,
    framebuffer: Framebuffer,
    //draw_context: DrawContext,
    //font: Font,
    smp: SMP.Information,
    architecture: Architecture,
    cpu_page_tables: CPUPageTables,
    slices: lib.EnumStruct(Slice.Name, Slice),

    pub const Architecture = switch (lib.cpu.arch) {
        .x86, .x86_64 => extern struct {
            rsdp_address: u64,
        },
        .aarch64 => extern struct {
            foo: u64 = 0,
        },
        .riscv64 => extern struct {
            foo: u64 = 0,
        },
        else => @compileError("Architecture not supported"),
    };

    pub const Slice = extern struct {
        offset: u32 = 0,
        size: u32 = 0,
        len: u32 = 0,
        alignment: u32 = 1,

        pub const Name = enum {
            bootloader_information, // The main struct
            memory_map_entries,
            page_counters,
            smps,
            file_list,
            bundle,
        };

        pub const count = lib.enumCount(Name);

        pub const TypeMap = blk: {
            var arr: [Slice.count]type = undefined;
            arr[@intFromEnum(Slice.Name.bootloader_information)] = Information;
            arr[@intFromEnum(Slice.Name.bundle)] = u8;
            arr[@intFromEnum(Slice.Name.file_list)] = u8;
            arr[@intFromEnum(Slice.Name.memory_map_entries)] = MemoryMapEntry;
            arr[@intFromEnum(Slice.Name.page_counters)] = u32;
            arr[@intFromEnum(Slice.Name.smps)] = SMP;
            break :blk arr;
        };

        pub inline fn dereference(slice: Slice, comptime slice_name: Slice.Name, bootloader_information: *const Information) []Slice.TypeMap[@intFromEnum(slice_name)] {
            const Type = Slice.TypeMap[@intFromEnum(slice_name)];
            const address = @intFromPtr(bootloader_information) + slice.offset;
            return @as([*]Type, @ptrFromInt(address))[0..slice.len];
        }
    };

    pub const SMP = extern struct {
        acpi_id: u32,
        lapic_id: u32,
        entry_point: u64,
        argument: u64,

        pub const Information = switch (lib.cpu.arch) {
            .x86, .x86_64 => extern struct {
                cpu_count: u32,
                bsp_lapic_id: u32,
            },
            .aarch64 => extern struct {
                cpu_count: u32,
            },
            .riscv64 => extern struct {
                cpu_count: u32,
            },
            else => @compileError("Architecture not supported"),
        };

        pub const Trampoline = extern struct {
            comptime {
                assert(lib.cpu.arch == .x86 or lib.cpu.arch == .x86_64);
            }

            pub const Argument = switch (lib.cpu.arch) {
                .x86, .x86_64 => extern struct {
                    hhdm: u64 align(8),
                    cr3: u32,
                    reserved: u16 = 0,
                    gdt_descriptor: arch.x86_64.GDT.Descriptor,
                    gdt: arch.x86_64.GDT,

                    comptime {
                        assert(@sizeOf(Argument) == 24 + @sizeOf(arch.x86_64.GDT));
                    }
                },
                else => {},
            };
        };
    };

    fn initializeMemoryMap(bootloader_information: *bootloader.Information, init: anytype) !usize {
        try init.deinitializeMemoryMap();

        const memory_map_entries = bootloader_information.getSlice(.memory_map_entries);
        var entry_index: usize = 0;
        while (try init.memory_map.next()) |entry| : (entry_index += 1) {
            memory_map_entries[entry_index] = entry;
        }

        return entry_index;
    }

    pub fn initialize(initialization: anytype, comptime bootloader_tag: lib.Bootloader, comptime protocol: Protocol) !noreturn {
        assert(@typeInfo(@TypeOf(initialization)) == .Pointer);
        assert(initialization.early_initialized);
        lib.log.info("Booting with bootloader {s} and boot protocol {s}", .{ @tagName(bootloader_tag), @tagName(protocol) });

        assert(initialization.framebuffer_initialized);
        assert(initialization.memory_map_initialized);
        assert(initialization.filesystem_initialized);

        const sector_size = initialization.filesystem.getSectorSize();

        const file_list_file_size = try initialization.filesystem.getFileSize("/files");
        const file_list_peek = try initialization.filesystem.sneakFile("/files", file_list_file_size);
        assert(file_list_peek.len > 0);
        var stream = lib.fixedBufferStream(file_list_peek);
        const file_list_reader = stream.reader();
        const bundle_uncompressed_size = try file_list_reader.readIntLittle(u32);
        assert(bundle_uncompressed_size > 0);
        const bundle_compressed_size = try file_list_reader.readIntLittle(u32);
        assert(bundle_compressed_size > 0);
        const bundle_file_count = try file_list_reader.readIntLittle(u32);
        assert(bundle_file_count > 0);

        const decompressor_state_allocation_size = 300 * lib.kb;

        const memory_map_entry_count = initialization.memory_map.getEntryCount();
        const cpu_count = try initialization.getCPUCount();

        const length_size_tuples = bootloader.LengthSizeTuples.new(.{
            .bootloader_information = .{
                .length = 1,
                .alignment = @alignOf(bootloader.Information),
            },
            .memory_map_entries = .{
                .length = memory_map_entry_count,
                .alignment = @alignOf(bootloader.MemoryMapEntry),
            },
            .smps = .{
                .length = cpu_count,
                .alignment = @max(@sizeOf(u64), @alignOf(bootloader.Information.SMP.Information)),
            },
            .page_counters = .{
                .length = memory_map_entry_count,
                .alignment = @alignOf(u32),
            },
            .file_list = .{
                .length = file_list_file_size,
                .alignment = 1,
            },
            .bundle = .{
                .length = bundle_uncompressed_size,
                .alignment = file_alignment,
            },
        });

        const extra_sizes = [2]usize{ decompressor_state_allocation_size, bundle_compressed_size };
        const aligned_extra_sizes = blk: {
            var result: [extra_sizes.len]usize = undefined;
            inline for (extra_sizes, &result) |extra_size, *element| {
                element.* = lib.alignForward(usize, extra_size, sector_size);
            }

            break :blk result;
        };

        const total_aligned_extra_size = blk: {
            var result: usize = 0;
            inline for (aligned_extra_sizes) |size| {
                result += size;
            }

            break :blk result;
        };

        var early_mmap_index: usize = 0;
        const length_size_tuples_size = length_size_tuples.getAlignedTotalSize();
        const total_allocation_size = length_size_tuples_size + total_aligned_extra_size;
        const total_allocation = blk: while (try initialization.memory_map.next()) |entry| : (early_mmap_index += 1) {
            if (entry.type == .usable) {
                if (entry.region.size >= total_allocation_size) {
                    break :blk .{
                        .index = early_mmap_index,
                        .region = entry.region,
                    };
                }
            }
        } else {
            return error.OutOfMemory;
        };

        const bootloader_information = total_allocation.region.address.toIdentityMappedVirtualAddress().access(*bootloader.Information);
        bootloader_information.* = bootloader.Information{
            .protocol = protocol,
            .bootloader = bootloader_tag,
            .version = .{ .major = 0, .minor = 1, .patch = 0 },
            .total_size = length_size_tuples.total_size,
            .entry_point = 0,
            .higher_half = lib.config.cpu_driver_higher_half_address,
            .stage = .early,
            .configuration = .{
                .memory_map_diff = 0,
            },
            .framebuffer = initialization.framebuffer,
            // .draw_context = .{},
            // .font = undefined,
            .cpu_driver_mappings = .{},
            .cpu_page_tables = undefined,
            .smp = switch (lib.cpu.arch) {
                .x86, .x86_64 => .{
                    .cpu_count = cpu_count,
                    .bsp_lapic_id = @as(*volatile u32, @ptrFromInt(0x0FEE00020)).*,
                },
                else => @compileError("Architecture not supported"),
            },
            .slices = length_size_tuples.createSlices(),
            .architecture = switch (lib.cpu.arch) {
                .x86, .x86_64 => .{
                    .rsdp_address = initialization.getRSDPAddress(),
                },
                else => @compileError("Architecture not supported"),
            },
        };

        const page_counters = bootloader_information.getSlice(.page_counters);
        @memset(page_counters, 0);

        // Make sure pages are allocated to host the bootloader information and fetch memory entries from firmware (only non-UEFI)
        if (bootloader_tag != .rise or protocol != .uefi) {
            page_counters[total_allocation.index] = bootloader_information.getAlignedTotalSize() >> lib.arch.page_shifter(lib.arch.valid_page_sizes[0]);

            const new_memory_map_entry_count = try bootloader_information.initializeMemoryMap(initialization);

            if (new_memory_map_entry_count != memory_map_entry_count) @panic("Memory map entry count mismatch");
        }

        const file_list = bootloader_information.getSlice(.file_list);
        if (file_list_peek.len == file_list_file_size) {
            lib.memcpy(file_list, file_list_peek);
        } else {
            @panic("Not able to fit in the cache");
        }

        try initialization.filesystem.deinitialize();

        const bootloader_information_total_aligned_size = bootloader_information.getAlignedTotalSize();
        const extra_allocation_region = total_allocation.region.offset(bootloader_information_total_aligned_size).shrinked(total_aligned_extra_size);
        const decompressor_state_buffer = extra_allocation_region.toIdentityMappedVirtualAddress().access(u8)[0..decompressor_state_allocation_size];
        const compressed_bundle_buffer = extra_allocation_region.offset(decompressor_state_allocation_size).toIdentityMappedVirtualAddress().access(u8)[0..lib.alignForward(usize, bundle_compressed_size, sector_size)];
        const compressed_bundle = try initialization.filesystem.readFile("/bundle", compressed_bundle_buffer);
        assert(compressed_bundle.len > 0);

        if (bootloader_tag == .rise and protocol == .uefi) {
            // Check if the memory map entry count matches here is not useful because probably it's going to be less as exiting boot services seems
            // like making some deallocations
            const new_memory_map_entry_count = @as(u32, @intCast(try bootloader_information.initializeMemoryMap(initialization)));
            if (new_memory_map_entry_count > memory_map_entry_count) {
                return Error.unexpected_memory_map_entry_count;
            }
            bootloader_information.configuration.memory_map_diff = @as(u8, @intCast(memory_map_entry_count - new_memory_map_entry_count));
        }

        // Check if the host entry still corresponds to the same index
        const memory_map_entries = bootloader_information.getMemoryMapEntries();
        const expected_host_region = memory_map_entries[total_allocation.index].region;
        assert(expected_host_region.address.value() == total_allocation.region.address.value());
        assert(expected_host_region.size == total_allocation.region.size);

        var compressed_bundle_stream = lib.fixedBufferStream(compressed_bundle);
        const decompressed_bundle = bootloader_information.getSlice(.bundle);
        assert(decompressed_bundle.len != 0);
        var decompressor_state_allocator = lib.FixedBufferAllocator.init(decompressor_state_buffer);
        var decompressor = try lib.deflate.decompressor(decompressor_state_allocator.allocator(), compressed_bundle_stream.reader(), null);
        const bytes = try decompressor.reader().readAll(decompressed_bundle);
        assert(bytes == bundle_uncompressed_size);
        if (decompressor.close()) |err| {
            return err;
        }

        // Empty region as this is no longer needed. Region was not marked as allocated so no need
        // to unmark it
        const free_slice = extra_allocation_region.toIdentityMappedVirtualAddress().access(u8);
        @memset(free_slice, 0);

        const page_allocator = PageAllocator{
            .allocate = Information.callbackAllocatePages,
            .context = bootloader_information,
            .context_type = .bootloader,
        };
        bootloader_information.cpu_page_tables = try CPUPageTables.initialize(page_allocator);

        const minimal_paging = privileged.arch.paging.Specific.fromPageTables(bootloader_information.cpu_page_tables);

        const cpu_file_descriptor = try bootloader_information.getFileDescriptor("cpu_driver");
        var elf_parser = try lib.ELF(64).Parser.init(cpu_file_descriptor.content);
        const program_headers = elf_parser.getProgramHeaders();

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

                    const aligned_size = lib.alignForward(u64, ph.size_in_memory, lib.arch.valid_page_sizes[0]);
                    const physical_allocation = try bootloader_information.allocatePages(aligned_size, lib.arch.valid_page_sizes[0], .{});
                    const physical_address = physical_allocation.address;
                    const virtual_address = VirtualAddress.new(ph.virtual_address);
                    const flags = Mapping.Flags{ .write = ph.flags.writable, .execute = ph.flags.executable };

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

                    // log.debug("Started mapping kernel section", .{});
                    try bootloader_information.cpu_page_tables.map(physical_address, virtual_address, aligned_size, flags);
                    // log.debug("Ended mapping kernel section", .{});

                    const dst_slice = physical_address.toIdentityMappedVirtualAddress().access([*]u8)[0..lib.safeArchitectureCast(ph.size_in_memory)];
                    const src_slice = cpu_file_descriptor.content[lib.safeArchitectureCast(ph.offset)..][0..lib.safeArchitectureCast(ph.size_in_file)];
                    // log.debug("Src slice: [0x{x}, 0x{x}]. Dst slice: [0x{x}, 0x{x}]", .{ @ptrToInt(src_slice.ptr), @ptrToInt(src_slice.ptr) + src_slice.len, @ptrToInt(dst_slice.ptr), @ptrToInt(dst_slice.ptr) + dst_slice.len });
                    if (!(dst_slice.len >= src_slice.len)) {
                        @panic("bios: segment allocated memory must be equal or greater than especified");
                    }

                    lib.memcpy(dst_slice, src_slice);
                },
                else => {
                    //log.warn("Unhandled PH {s}", .{@tagName(ph.type)});
                },
            }
        }

        //for (bootloader_information.getMemoryMapEntries()[0..memory_map_entry_count]) |entry| {
        for (bootloader_information.getMemoryMapEntries()) |entry| {
            if (entry.type == .usable) {
                try minimal_paging.map(entry.region.address, entry.region.address.toHigherHalfVirtualAddress(), lib.alignForward(u64, entry.region.size, lib.arch.valid_page_sizes[0]), .{ .write = true, .execute = false }, page_allocator);
            }
        }

        try minimal_paging.map(total_allocation.region.address, total_allocation.region.address.toIdentityMappedVirtualAddress(), bootloader_information.getAlignedTotalSize(), .{ .write = true, .execute = false }, page_allocator);
        try initialization.ensureLoaderIsMapped(minimal_paging, page_allocator, bootloader_information);

        const framebuffer_physical_address = PhysicalAddress.new(if (bootloader_information.bootloader == .limine) bootloader_information.framebuffer.address - lib.config.cpu_driver_higher_half_address else bootloader_information.framebuffer.address);
        try minimal_paging.map(framebuffer_physical_address, framebuffer_physical_address.toHigherHalfVirtualAddress(), lib.alignForward(u64, bootloader_information.framebuffer.getSize(), lib.arch.valid_page_sizes[0]), .{ .write = true, .execute = false }, page_allocator);
        bootloader_information.framebuffer.address = framebuffer_physical_address.toHigherHalfVirtualAddress().value();

        try initialization.ensureStackIsMapped(minimal_paging, page_allocator);

        switch (lib.cpu.arch) {
            .x86, .x86_64 => {
                const apic_base_physical_address = privileged.arch.x86_64.registers.IA32_APIC_BASE.read().getAddress();
                try minimal_paging.map(apic_base_physical_address, apic_base_physical_address.toHigherHalfVirtualAddress(), lib.arch.valid_page_sizes[0], .{
                    .write = true,
                    .cache_disable = true,
                    .global = true,
                }, page_allocator);
            },
            else => @compileError("Not supported"),
        }

        // bootloader_information.initializeSMP(madt);

        bootloader_information.entry_point = elf_parser.getEntryPoint();

        if (bootloader_information.entry_point != 0) {
            lib.log.info("Jumping to kernel...", .{});
            bootloader.arch.x86_64.jumpToKernel(bootloader_information, minimal_paging);
        } else return Error.no_entry_point_found;
    }

    pub const Error = error{
        file_not_found,
        filesystem_initialization_failed,
        unexpected_memory_map_entry_count,
        no_entry_point_found,
    };

    pub fn getAlignedTotalSize(information: *Information) u32 {
        if (information.total_size == 0) @panic("Information.getAlignedTotalSize");
        return lib.alignForward(u32, information.total_size, lib.arch.valid_page_sizes[0]);
    }

    pub inline fn getSlice(information: *const Information, comptime offset_name: Slice.Name) []Slice.TypeMap[@intFromEnum(offset_name)] {
        const slice_offset = information.slices.array.values[@intFromEnum(offset_name)];
        return slice_offset.dereference(offset_name, information);
    }

    pub fn getMemoryMapEntryCount(information: *Information) usize {
        return information.getSlice(.memory_map_entries).len - information.configuration.memory_map_diff;
    }

    pub fn getMemoryMapEntries(information: *Information) []MemoryMapEntry {
        return information.getSlice(.memory_map_entries)[0..information.getMemoryMapEntryCount()];
    }

    pub fn getPageCounters(information: *Information) []u32 {
        return information.getSlice(.page_counters)[0..information.getMemoryMapEntryCount()];
    }

    pub const IntegrityError = error{
        bad_slice_alignment,
        bad_slice_size,
        bad_total_size,
        bad_struct_offset,
    };

    pub fn checkIntegrity(information: *const Information) !void {
        if (information.last_struct_offset != last_struct_offset) {
            return IntegrityError.bad_struct_offset;
        }

        const original_total_size = information.total_size;
        var total_size: u32 = 0;
        inline for (Information.Slice.TypeMap, 0..) |T, index| {
            const slice = information.slices.array.values[index];

            if (slice.alignment < @alignOf(T)) {
                return IntegrityError.bad_slice_alignment;
            }

            if (slice.len * @sizeOf(T) != slice.size) {
                return IntegrityError.bad_slice_size;
            }

            total_size = lib.alignForward(u32, total_size, slice.alignment);
            total_size += lib.alignForward(u32, slice.size, slice.alignment);
        }

        if (total_size != original_total_size) {
            return IntegrityError.bad_total_size;
        }
    }

    pub fn allocatePages(bootloader_information: *Information, size: u64, alignment: u64, options: PageAllocator.AllocateOptions) Allocator.Allocate.Error!PhysicalMemoryRegion {
        const allocation = blk: {
            if (bootloader_information.stage != .cpu) {
                if (size & lib.arch.page_mask(lib.arch.valid_page_sizes[0]) != 0) return Allocator.Allocate.Error.OutOfMemory;
                if (alignment & lib.arch.page_mask(lib.arch.valid_page_sizes[0]) != 0) return Allocator.Allocate.Error.OutOfMemory;

                const four_kb_pages = @as(u32, @intCast(@divExact(size, lib.arch.valid_page_sizes[0])));

                const entries = bootloader_information.getMemoryMapEntries();
                const page_counters = bootloader_information.getPageCounters();

                for (entries, 0..) |entry, entry_index| {
                    const busy_size = @as(u64, page_counters[entry_index]) * lib.arch.valid_page_sizes[0];
                    const size_left = entry.region.size - busy_size;
                    const target_address = entry.region.address.offset(busy_size);

                    if (entry.type == .usable and target_address.value() <= lib.maxInt(usize) and size_left > size and entry.region.address.value() != 0) {
                        if (entry.region.address.isAligned(alignment)) {
                            const result = PhysicalMemoryRegion.new(.{
                                .address = target_address,
                                .size = size,
                            });

                            @memset(@as([*]u8, @ptrFromInt(lib.safeArchitectureCast(result.address.value())))[0..lib.safeArchitectureCast(result.size)], 0);

                            page_counters[entry_index] += four_kb_pages;

                            break :blk result;
                        }
                    }
                }

                if (options.space_waste_allowed_to_guarantee_alignment > 0) {
                    for (entries, 0..) |entry, entry_index| {
                        const busy_size = @as(u64, page_counters[entry_index]) * lib.arch.valid_page_sizes[0];
                        const size_left = entry.region.size - busy_size;
                        const target_address = entry.region.address.offset(busy_size);

                        if (entry.type == .usable and target_address.value() <= lib.maxInt(usize) and size_left > size and entry.region.address.value() != 0) {
                            const aligned_address = lib.alignForward(u64, target_address.value(), alignment);
                            const difference = aligned_address - target_address.value();
                            const allowed_quota = alignment / options.space_waste_allowed_to_guarantee_alignment;

                            if (aligned_address + size < entry.region.address.offset(entry.region.size).value() and difference <= allowed_quota) {
                                const result = PhysicalMemoryRegion.new(.{
                                    .address = PhysicalAddress.new(aligned_address),
                                    .size = size,
                                });

                                @memset(@as([*]u8, @ptrFromInt(lib.safeArchitectureCast(result.address.value())))[0..lib.safeArchitectureCast(result.size)], 0);
                                page_counters[entry_index] += @as(u32, @intCast(difference + size)) >> lib.arch.page_shifter(lib.arch.valid_page_sizes[0]);

                                break :blk result;
                            }
                        }
                    }
                }
            }

            return Allocator.Allocate.Error.OutOfMemory;
        };

        return allocation;
    }

    pub fn callbackAllocatePages(context: ?*anyopaque, size: u64, alignment: u64, options: PageAllocator.AllocateOptions) Allocator.Allocate.Error!PhysicalMemoryRegion {
        const bootloader_information = @as(*Information, @ptrCast(@alignCast(context)));
        return try bootloader_information.allocatePages(size, alignment, options);
    }

    pub fn heapAllocate(bootloader_information: *Information, size: u64, alignment: u64) !Allocator.Allocate.Result {
        if (bootloader_information.stage != .cpu) {
            for (&bootloader_information.heap.regions) |*region| {
                if (region.size > size) {
                    const result = .{
                        .address = region.address.value(),
                        .size = size,
                    };
                    region.size -= size;
                    region.address.addOffset(size);
                    return result;
                }
            }
            const size_to_page_allocate = lib.alignForward(u64, size, lib.arch.valid_page_sizes[0]);
            for (&bootloader_information.heap.regions) |*region| {
                if (region.size == 0) {
                    const allocated_region = try bootloader_information.page_allocator.allocateBytes(size_to_page_allocate, lib.arch.valid_page_sizes[0]);
                    region.* = .{
                        .address = PhysicalAddress.new(allocated_region.address),
                        .size = allocated_region.size,
                    };
                    const result = .{
                        .address = region.address.value(),
                        .size = size,
                    };
                    region.address.addOffset(size);
                    region.size -= size;
                    return result;
                }
            }

            _ = alignment;
        }

        return Allocator.Allocate.Error.OutOfMemory;
    }

    pub fn getFileDescriptor(bootloader_information: *bootloader.Information, wanted_file_name: []const u8) !FileDescriptor {
        const file_list = bootloader_information.getSlice(.file_list);

        var index: usize = 0;
        index += 2 * @sizeOf(u32);
        const file_count = @as(*align(1) const u32, @ptrCast(&file_list[index])).*;
        index += @sizeOf(u32);
        var file_index: u32 = 0;

        while (file_index < file_count) : (file_index += 1) {
            const file_name_len_offset = 2 * @sizeOf(u32);
            const file_name_len = file_list[index + file_name_len_offset];
            const file_name_offset = file_name_len_offset + @sizeOf(u8);
            const file_name = file_list[index + file_name_offset ..][0..file_name_len];

            if (lib.equal(u8, wanted_file_name, file_name)) {
                const file_offset = @as(*align(1) const u32, @ptrCast(&file_list[index + 0])).*;
                const file_size = @as(*align(1) const u32, @ptrCast(&file_list[index + @sizeOf(u32)])).*;
                const bundle = bootloader_information.getSlice(.bundle);
                const file_content = bundle[file_offset..][0..file_size];

                return FileDescriptor{
                    .name = file_name,
                    .content = file_content,
                };
            }

            const offset_to_add = file_name_offset + file_name.len;
            index += offset_to_add;
        }

        return Error.file_not_found;
    }
};

pub const FileDescriptor = struct {
    name: []const u8,
    content: []const u8,
};

pub const CPUDriverMappings = extern struct {
    text: Mapping = .{},
    data: Mapping = .{},
    rodata: Mapping = .{},
};

const Mapping = privileged.Mapping;

pub const MemoryMapEntry = extern struct {
    region: PhysicalMemoryRegion align(8),
    type: Type align(8),

    const Type = enum(u64) {
        usable = 0,
        reserved = 1,
        bad_memory = 2,
    };

    pub fn getFreeRegion(mmap_entry: MemoryMapEntry, page_counter: u32) PhysicalMemoryRegion {
        return mmap_entry.region.offset(page_counter << lib.arch.page_shifter(lib.arch.valid_page_sizes[0]));
    }

    comptime {
        assert(@sizeOf(MemoryMapEntry) == @sizeOf(u64) * 3);
    }
};

pub const Framebuffer = extern struct {
    address: u64,
    pitch: u32,
    width: u32,
    height: u32,
    bpp: u16,
    red_mask: ColorMask,
    green_mask: ColorMask,
    blue_mask: ColorMask,
    memory_model: u8,
    reserved: u8 = 0,

    pub const ColorMask = extern struct {
        size: u8 = 0,
        shift: u8 = 0,
    };

    pub const VideoMode = extern struct {
        foo: u32 = 0,
    };

    pub inline fn getSize(framebuffer: Framebuffer) u32 {
        return framebuffer.pitch * framebuffer.height;
    }
};

pub const LengthSizeTuples = extern struct {
    tuples: Tuples,
    total_size: u32 = 0,

    const Tuples = lib.EnumStruct(Information.Slice.Name, Tuple);

    const count = Information.Slice.count;

    pub const Tuple = extern struct {
        length: u32,
        alignment: u32,
        size: u32 = 0,
        reserved: u32 = 0,
    };

    pub fn new(fields: Tuples.Struct) LengthSizeTuples {
        var tuples = LengthSizeTuples{
            .tuples = .{
                .fields = fields,
            },
        };

        var total_size: u32 = 0;

        inline for (Information.Slice.TypeMap, 0..) |T, index| {
            const tuple = &tuples.tuples.array.values[index];
            const size = tuple.length * @sizeOf(T);
            tuple.alignment = if (tuple.alignment < @alignOf(T)) @alignOf(T) else tuple.alignment;
            total_size = lib.alignForward(u32, total_size, tuple.alignment);
            total_size += lib.alignForward(u32, size, tuple.alignment);
            tuple.size = size;
        }

        tuples.total_size = total_size;

        return tuples;
    }

    pub fn createSlices(tuples: LengthSizeTuples) lib.EnumStruct(Information.Slice.Name, Information.Slice) {
        var slices = lib.zeroes(lib.EnumStruct(Information.Slice.Name, Information.Slice));
        var allocated_size: u32 = 0;

        for (&slices.array.values, 0..) |*slice, index| {
            const tuple = tuples.tuples.array.values[index];
            const length = tuple.length;
            const size = lib.alignForward(u32, tuple.size, tuple.alignment);

            allocated_size = lib.alignForward(u32, allocated_size, tuple.alignment);
            slice.* = .{
                .offset = allocated_size,
                .len = length,
                .size = tuple.size,
                .alignment = tuple.alignment,
            };

            allocated_size += size;
        }

        if (allocated_size != tuples.total_size) @panic("Extra allocation size must match bootloader allocated extra size");

        return slices;
    }

    pub fn getAlignedTotalSize(tuples: LengthSizeTuples) u32 {
        if (tuples.total_size == 0) @panic("LengthSizeTuples.getAlignedTotalSize");
        return lib.alignForward(u32, tuples.total_size, lib.arch.valid_page_sizes[0]);
    }
};

pub const Stage = enum(u32) {
    early = 0,
    only_graphics = 1,
    trampoline = 2,
    cpu = 3,
};
