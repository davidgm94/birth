const bootloader = @This();

pub const BIOS = @import("bootloader/bios.zig");
pub const UEFI = @import("bootloader/uefi.zig");
pub const limine = @import("bootloader/limine/limine.zig");
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
const PhysicalAddress = privileged.PhysicalAddress;
const VirtualAddress = privileged.VirtualAddress;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const VirtualMemoryRegion = privileged.VirtualMemoryRegion;
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

const file_alignment = 0x200;
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
    draw_context: DrawContext,
    font: Font,
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
            file_contents,
            file_names,
            files,
            memory_map_entries,
            page_counters,
            smps,
        };

        pub const count = lib.enumCount(Name);

        pub const TypeMap = blk: {
            var arr: [Slice.count]type = undefined;
            arr[@enumToInt(Slice.Name.bootloader_information)] = Information;
            arr[@enumToInt(Slice.Name.file_contents)] = u8;
            arr[@enumToInt(Slice.Name.file_names)] = u8;
            arr[@enumToInt(Slice.Name.files)] = File;
            arr[@enumToInt(Slice.Name.memory_map_entries)] = MemoryMapEntry;
            arr[@enumToInt(Slice.Name.page_counters)] = u32;
            arr[@enumToInt(Slice.Name.smps)] = SMP;
            break :blk arr;
        };

        pub inline fn dereference(slice: Slice, comptime slice_name: Slice.Name, bootloader_information: *const Information) []Slice.TypeMap[@enumToInt(slice_name)] {
            const Type = Slice.TypeMap[@enumToInt(slice_name)];
            const address = @ptrToInt(bootloader_information) + slice.offset;
            return @intToPtr([*]Type, address)[0..slice.len];
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

    fn initializeMemoryMap(bootloader_information: *bootloader.Information, memory_map: Initialization.MemoryMap) !usize {
        try memory_map.deinitialize(memory_map.context);

        const memory_map_entries = bootloader_information.getSlice(.memory_map_entries);
        var entry_index: usize = 0;
        while (try memory_map.next(memory_map.context)) |entry| : (entry_index += 1) {
            memory_map_entries[entry_index] = entry;
        }

        return entry_index;
    }

    pub fn initialize(filesystem: Initialization.Filesystem, memory_map: Initialization.MemoryMap, framebuffer: Initialization.Framebuffer, virtual_address_space: Initialization.VirtualAddressSpace, rsdp: *ACPI.RSDP.Descriptor1, bootloader_tag: lib.Bootloader, protocol: Protocol) anyerror!noreturn {
        lib.log.info("Booting with bootloader {s} and boot protocol {s}", .{ @tagName(bootloader_tag), @tagName(protocol) });
        const framebuffer_data = try framebuffer.initialize(framebuffer.context);
        filesystem.initialize(filesystem.context) catch return Initialization.Error.filesystem_initialization_failed;
        const file_type_enums = lib.fields(File.Type);

        var total_file_size: usize = 0;
        var total_aligned_file_size: u32 = 0;
        var total_file_name_size: usize = 0;
        const total_file_count: u32 = file_type_enums.len;

        inline for (file_type_enums) |file_type_enum| {
            const file_name = file_type_enum.name;
            const file_type = @field(File.Type, file_name);
            const file_descriptor = filesystem.get_file_descriptor(filesystem.context, file_type) catch return switch (file_type) {
                .cpu => Initialization.Error.cpu_driver_not_found,
                .init => Initialization.Error.init_not_found,
                .font => Initialization.Error.font_not_found,
            };

            total_file_size += file_descriptor.size;
            total_aligned_file_size += lib.alignForwardGeneric(u32, file_descriptor.size, file_alignment);
            total_file_name_size += file_descriptor.path.len;
        }

        try filesystem.deinitialize(filesystem.context);
        const cpu_driver_index = @enumToInt(File.Type.cpu);

        try memory_map.initialize(memory_map.context);
        var memory_map_entry_count = try memory_map.get_memory_map_entry_count(memory_map.context);
        const madt_header = rsdp.findTable(.APIC) orelse @panic("Can't find MADT");
        const madt = @ptrCast(*align(1) const ACPI.MADT, madt_header);
        const cpu_count = madt.getCPUCount();

        const length_size_tuples = bootloader.LengthSizeTuples.new(.{
            .bootloader_information = .{
                .length = 1,
                .alignment = @alignOf(bootloader.Information),
            },
            .file_names = .{
                .length = @intCast(u32, total_file_name_size),
                .alignment = 1,
            },
            .files = .{
                .length = total_file_count,
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

        var host_entry_index: usize = 0;
        const host_entry_region = blk: {
            if (bootloader_tag == .rise and protocol == .uefi) {
                lib.log.debug("A", .{});
                const host_region = try (memory_map.get_host_region orelse @panic("No host region"))(memory_map.context, length_size_tuples);
                break :blk host_region;
            } else {
                lib.log.debug("B", .{});
                const host_entry = while (try memory_map.next(memory_map.context)) |entry| : (host_entry_index += 1) {
                    lib.log.debug("host_entry_region start", .{});
                    if (entry.type == .usable and entry.region.size > length_size_tuples.getAlignedTotalSize()) {
                        lib.log.debug("host_entry_region end", .{});
                        break :blk entry.region;
                    }
                    lib.log.debug("host_entry_region end", .{});
                } else @panic("No memory map entry is suitable for hosting bootloader information");
                _ = host_entry;
            }
        };

        const bootloader_information = host_entry_region.address.toIdentityMappedVirtualAddress().access(*bootloader.Information);
        bootloader_information.* = .{
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
            .framebuffer = framebuffer_data,
            .draw_context = .{},
            .font = undefined,
            .cpu_driver_mappings = .{},
            .cpu_page_tables = undefined,
            .smp = switch (lib.cpu.arch) {
                .x86, .x86_64 => .{
                    .cpu_count = cpu_count,
                    .bsp_lapic_id = @intToPtr(*volatile u32, 0x0FEE00020).*,
                },
                else => @compileError("Architecture not supported"),
            },
            .slices = length_size_tuples.createSlices(),
            .architecture = .{
                .rsdp_address = @ptrToInt(rsdp),
            },
        };

        const page_counters = bootloader_information.getSlice(.page_counters);
        for (page_counters) |*page_counter| {
            page_counter.* = 0;
        }

        {
            // Make sure pages are allocated to host the bootloader information and fetch memory entries from firmware (only non-UEFI
            if (bootloader_tag != .rise or protocol != .uefi) {
                page_counters[host_entry_index] = bootloader_information.getAlignedTotalSize() >> lib.arch.page_shifter(lib.arch.valid_page_sizes[0]);

                const new_memory_map_entry_count = try bootloader_information.initializeMemoryMap(memory_map);

                if (new_memory_map_entry_count != memory_map_entry_count) @panic("Memory map entry count mismatch");
            }

            const file_content_buffer = bootloader_information.getSlice(.file_contents);
            const file_name_buffer = bootloader_information.getSlice(.file_names);
            const file_slice = bootloader_information.getSlice(.files);
            if (file_slice.len == 0) @panic("Files 0");

            var file_content_offset: u32 = 0;
            var file_name_offset: u32 = 0;

            inline for (lib.fields(File.Type), 0..) |file_type_enum, file_index| {
                const file_type = @field(File.Type, file_type_enum.name);
                const file_descriptor = try filesystem.get_file_descriptor(filesystem.context, file_type);
                const path_len = @intCast(u32, file_descriptor.path.len);
                lib.copy(u8, file_name_buffer[file_name_offset .. file_name_offset + path_len], file_descriptor.path);
                const aligned_file_size = lib.alignForwardGeneric(u32, file_descriptor.size, file_alignment);
                const file_buffer = file_content_buffer[file_content_offset .. file_content_offset + aligned_file_size];

                const file = filesystem.read_file(filesystem.context, file_descriptor.path, file_buffer) catch {
                    switch (file_descriptor.type) {
                        .cpu => return Initialization.Error.cpu_driver_not_found,
                        .font => return Initialization.Error.font_not_found,
                        .init => return Initialization.Error.init_not_found,
                    }
                };
                _ = file;
                file_slice[file_index] = .{
                    .content_offset = file_content_offset,
                    .content_size = file_descriptor.size,
                    .path_offset = file_name_offset,
                    .path_size = path_len,
                    .type = file_descriptor.type,
                };
                file_content_offset += aligned_file_size;
                file_name_offset += path_len;
            }

            if (file_content_offset != file_content_buffer.len) @panic("File content slice size mismatch");
            if (file_name_offset != file_name_buffer.len) @panic("File name slice size mismatch");

            if (bootloader_tag == .rise and protocol == .uefi) {
                // Check if the memory map entry count matches here is not useful because probably it's going to be less as exiting boot services seems
                // like making some deallocations
                memory_map_entry_count = @intCast(u32, try bootloader_information.initializeMemoryMap(memory_map));
            }
        }

        const page_allocator = PageAllocator{
            .allocate = Information.callbackAllocatePages,
            .context = bootloader_information,
            .context_type = .bootloader,
        };
        bootloader_information.cpu_page_tables = try CPUPageTables.initialize(page_allocator);

        const minimal_paging = privileged.arch.paging.Specific.fromPageTables(bootloader_information.cpu_page_tables);

        const cpu_driver_file_descriptor = bootloader_information.getSlice(.files)[cpu_driver_index];
        const cpu_driver_file_content = cpu_driver_file_descriptor.getContent(bootloader_information);
        var elf_parser = try lib.ELF(64).Parser.init(cpu_driver_file_content);
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

                    const aligned_size = lib.alignForwardGeneric(u64, ph.size_in_memory, lib.arch.valid_page_sizes[0]);
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
                    const src_slice = cpu_driver_file_content[lib.safeArchitectureCast(ph.offset)..][0..lib.safeArchitectureCast(ph.size_in_file)];
                    // log.debug("Src slice: [0x{x}, 0x{x}]. Dst slice: [0x{x}, 0x{x}]", .{ @ptrToInt(src_slice.ptr), @ptrToInt(src_slice.ptr) + src_slice.len, @ptrToInt(dst_slice.ptr), @ptrToInt(dst_slice.ptr) + dst_slice.len });
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

        for (bootloader_information.getMemoryMapEntries()[0..memory_map_entry_count]) |entry| {
            if (entry.type == .usable) {
                try minimal_paging.map(entry.region.address, entry.region.address.toHigherHalfVirtualAddress(), lib.alignForwardGeneric(u64, entry.region.size, lib.arch.valid_page_sizes[0]), .{ .write = true, .execute = false }, page_allocator);
            }
        }

        try minimal_paging.map(host_entry_region.address, host_entry_region.address.toIdentityMappedVirtualAddress(), bootloader_information.getAlignedTotalSize(), .{ .write = true, .execute = false }, page_allocator);

        try virtual_address_space.ensure_loader_is_mapped(virtual_address_space.context, minimal_paging, page_allocator, bootloader_information);

        const framebuffer_physical_address = PhysicalAddress.new(if (bootloader_information.bootloader == .limine) bootloader_information.framebuffer.address - lib.config.cpu_driver_higher_half_address else bootloader_information.framebuffer.address);
        try minimal_paging.map(framebuffer_physical_address, framebuffer_physical_address.toHigherHalfVirtualAddress(), lib.alignForwardGeneric(u64, bootloader_information.framebuffer.getSize(), lib.arch.valid_page_sizes[0]), .{ .write = true, .execute = false }, page_allocator);
        bootloader_information.framebuffer.address = framebuffer_physical_address.toHigherHalfVirtualAddress().value();

        try virtual_address_space.ensure_stack_is_mapped(virtual_address_space.context, minimal_paging, page_allocator);

        // bootloader_information.initializeSMP(madt);

        bootloader_information.entry_point = elf_parser.getEntryPoint();

        if (bootloader_information.entry_point != 0) {
            lib.log.info("Jumping to kernel...", .{});
            bootloader.arch.x86_64.jumpToKernel(bootloader_information, minimal_paging);
        } else @panic("No entry point");
    }

    pub const Initialization = struct {
        pub const Error = error{
            cpu_driver_not_found,
            font_not_found,
            init_not_found,
            filesystem_initialization_failed,
        };

        pub const Filesystem = extern struct {
            context: ?*anyopaque,
            initialize: *const fn (context: ?*anyopaque) anyerror!void,
            deinitialize: *const fn (context: ?*anyopaque) anyerror!void,
            get_file_descriptor: *const fn (context: ?*anyopaque, file_type: File.Type) anyerror!Descriptor,
            read_file: *const fn (context: ?*anyopaque, file_path: []const u8, file_buffer: []u8) anyerror![]const u8,

            pub const Descriptor = struct {
                path: []const u8,
                size: u32,
                type: File.Type,
            };
        };

        pub const MemoryMap = extern struct {
            context: ?*anyopaque,
            get_memory_map_entry_count: *const fn (context: ?*anyopaque) anyerror!u32,
            initialize: *const fn (context: ?*anyopaque) anyerror!void,
            deinitialize: *const fn (context: ?*anyopaque) anyerror!void,
            next: *const fn (context: ?*anyopaque) anyerror!?MemoryMapEntry,
            get_host_region: ?*const fn (context: ?*anyopaque, length_size_tuples: LengthSizeTuples) anyerror!PhysicalMemoryRegion,
        };

        pub const Framebuffer = extern struct {
            context: ?*anyopaque,
            initialize: *const fn (context: ?*anyopaque) anyerror!bootloader.Framebuffer,
        };

        pub const VirtualAddressSpace = extern struct {
            context: ?*anyopaque,
            ensure_loader_is_mapped: *const fn (context: ?*anyopaque, paging: paging.Specific, page_allocator: PageAllocator, bootloader_information: *bootloader.Information) anyerror!void,
            ensure_stack_is_mapped: *const fn (context: ?*anyopaque, paging: paging.Specific, page_allocator: PageAllocator) anyerror!void,
        };
    };

    pub fn initializeSMP(bootloader_information: *Information, madt: *const ACPI.MADT) void {
        if (bootloader_information.bootloader != .rise) @panic("Protocol not supported");

        const smp_records = bootloader_information.getSlice(.smps);

        switch (lib.cpu.arch) {
            .x86, .x86_64 => {
                const cr3 = bootloader_information.virtual_address_space.arch.cr3;
                if (@bitCast(u64, cr3) > lib.maxInt(u32)) {
                    lib.log.err("CR3: 0x{x}, {}", .{ @bitCast(u64, cr3), cr3 });
                    @panic("CR3 overflow");
                }

                const cpuid = lib.arch.x86_64.cpuid;
                const lapicWrite = privileged.arch.x86_64.APIC.lapicWrite;

                if (cpuid(1).edx & (1 << 9) == 0) {
                    @panic("No APIC detected");
                }

                var iterator = madt.getIterator();
                var smp_index: usize = 0;

                const smp_trampoline_physical_address = PhysicalAddress.new(@ptrToInt(&arch.x86_64.smp_trampoline));
                // Sanity checks
                const trampoline_argument_symbol = @extern(*SMP.Trampoline.Argument, .{ .name = "smp_trampoline_arg_start" });
                const smp_core_booted_symbol = @extern(*bool, .{ .name = "smp_core_booted" });
                const trampoline_argument_start = @ptrToInt(trampoline_argument_symbol);
                const trampoline_argument_offset = @intCast(u32, trampoline_argument_start - smp_trampoline_physical_address.value());
                const smp_core_booted_offset = @intCast(u32, @ptrToInt(smp_core_booted_symbol) - smp_trampoline_physical_address.value());
                if (!lib.isAligned(trampoline_argument_start, @alignOf(SMP.Trampoline.Argument))) @panic("SMP trampoline argument alignment must match");
                const trampoline_argument_end = @ptrToInt(@extern(*u8, .{ .name = "smp_trampoline_arg_end" }));
                lib.log.debug("Trampoline arg start: 0x{x}, end: 0x{x}", .{ trampoline_argument_start, trampoline_argument_end });
                const trampoline_argument_size = trampoline_argument_end - trampoline_argument_start;
                lib.log.debug("Trampoline argument size: {}", .{trampoline_argument_size});
                if (trampoline_argument_size != @sizeOf(SMP.Trampoline.Argument)) {
                    @panic("SMP trampoline argument size must match");
                }

                const smp_trampoline_size = @ptrToInt(@extern(*u8, .{ .name = "smp_trampoline_end" })) - smp_trampoline_physical_address.value();
                if (smp_trampoline_size > lib.arch.valid_page_sizes[0]) {
                    @panic("SMP trampoline too big");
                }

                const smp_trampoline = @intCast(u32, switch (lib.cpu.arch) {
                    .x86 => smp_trampoline_physical_address.toIdentityMappedVirtualAddress().value(),
                    .x86_64 => blk: {
                        const page_counters = bootloader_information.getPageCounters();
                        for (bootloader_information.getMemoryMapEntries(), 0..) |memory_map_entry, index| {
                            if (memory_map_entry.type == .usable and memory_map_entry.region.address.value() < lib.mb and lib.isAligned(memory_map_entry.region.address.value(), lib.arch.valid_page_sizes[0])) {
                                const page_counter = &page_counters[index];
                                const offset = page_counter.* * lib.arch.valid_page_sizes[0];
                                if (offset < memory_map_entry.region.size) {
                                    page_counter.* += 1;
                                    const smp_trampoline_buffer_region = memory_map_entry.region.offset(offset).toIdentityMappedVirtualAddress();

                                    privileged.arch.x86_64.paging.setMappingFlags(&bootloader_information.virtual_address_space, smp_trampoline_buffer_region.address.value(), .{
                                        .write = true,
                                        .execute = true,
                                        .global = true,
                                    }) catch @panic("can't set smp trampoline flags");

                                    const smp_trampoline_buffer = smp_trampoline_buffer_region.access(u8);
                                    const smp_trampoline_region = PhysicalMemoryRegion.new(smp_trampoline_physical_address, smp_trampoline_size);
                                    const smp_trampoline_source = smp_trampoline_region.toIdentityMappedVirtualAddress().access(u8);

                                    lib.copy(u8, smp_trampoline_buffer, smp_trampoline_source);
                                    break :blk smp_trampoline_buffer_region.address.value();
                                }
                            }
                        }

                        @panic("No suitable region found for SMP trampoline");
                    },
                    else => @compileError("Architecture not supported"),
                });

                const trampoline_argument = @intToPtr(*SMP.Trampoline.Argument, smp_trampoline + trampoline_argument_offset);
                trampoline_argument.* = .{
                    .hhdm = bootloader_information.higher_half,
                    .cr3 = @intCast(u32, @bitCast(u64, cr3)),
                    .gdt_descriptor = undefined,
                    .gdt = .{},
                };

                trampoline_argument.gdt_descriptor = trampoline_argument.gdt.getDescriptor();

                const smp_core_booted = @intToPtr(*bool, smp_trampoline + smp_core_booted_offset);

                while (iterator.next()) |entry| {
                    switch (entry.type) {
                        .LAPIC => {
                            const lapic_entry = @fieldParentPtr(ACPI.MADT.LAPIC, "record", entry);
                            const lapic_id = @as(u32, lapic_entry.APIC_ID);
                            smp_records[smp_index] = .{
                                .acpi_id = lapic_entry.ACPI_processor_UID,
                                .lapic_id = lapic_id,
                                .entry_point = 0,
                                .argument = 0,
                            };

                            if (lapic_entry.APIC_ID == bootloader_information.smp.bsp_lapic_id) {
                                smp_index += 1;
                                continue;
                            }

                            lapicWrite(.icr_high, lapic_id << 24);
                            lapicWrite(.icr_low, 0x4500);

                            arch.x86_64.delay(10_000_000);

                            const icr_low = (smp_trampoline >> 12) | 0x4600;
                            lib.log.debug("ICR low: 0x{x}", .{icr_low});
                            lapicWrite(.icr_high, lapic_id << 24);
                            lapicWrite(.icr_low, icr_low);

                            for (0..100) |_| {
                                if (@cmpxchgStrong(bool, smp_core_booted, true, false, .SeqCst, .SeqCst) == null) {
                                    lib.log.debug("Booted core #{}", .{lapic_id});
                                    break;
                                }

                                arch.x86_64.delay(10_000_000);
                            } else @panic("SMP not booted");
                        },
                        .x2APIC => @panic("x2APIC"),
                        else => {
                            lib.log.warn("Unhandled {s} entry", .{@tagName(entry.type)});
                        },
                    }
                }

                lib.log.debug("Enabled all cores!", .{});
            },
            else => @compileError("Architecture not supported"),
        }
    }

    pub fn getAlignedTotalSize(information: *Information) u32 {
        if (information.total_size == 0) @panic("Information.getAlignedTotalSize");
        return lib.alignForwardGeneric(u32, information.total_size, lib.arch.valid_page_sizes[0]);
    }

    pub fn getFiles(information: *Information) []File {
        const files_slice_struct = information.slices.fields.files;
        const files = @intToPtr([*]File, @ptrToInt(information) + files_slice_struct.offset)[0..files_slice_struct.len];
        return files;
    }

    pub inline fn getSliceOffset(information: *const Information, comptime offset_name: Slice.Name) Slice {
        const slice_offset = information.slices.array.values[@enumToInt(offset_name)];
        return slice_offset;
    }

    pub inline fn getSlice(information: *const Information, comptime offset_name: Slice.Name) []Slice.TypeMap[@enumToInt(offset_name)] {
        const slice_offset = information.slices.array.values[@enumToInt(offset_name)];
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
    // TODO: further checks
    pub fn checkIntegrity(information: *const Information) !void {
        if (information.last_struct_offset != last_struct_offset) return IntegrityError.bad_struct_offset;
        const original_total_size = information.total_size;
        var total_size: u32 = 0;
        inline for (Information.Slice.TypeMap, 0..) |T, index| {
            const slice = information.slices.array.values[index];
            if (slice.alignment < @alignOf(T)) {
                lib.log.err("Bad alignment of {}. Current: {}. Before: {}", .{ T, @alignOf(T), slice.alignment });
                return IntegrityError.bad_slice_alignment;
            }
            if (slice.len * @sizeOf(T) != slice.size) {
                return IntegrityError.bad_slice_size;
            }
            total_size = lib.alignForwardGeneric(u32, total_size, slice.alignment);
            total_size += lib.alignForwardGeneric(u32, slice.size, slice.alignment);
        }

        if (total_size != original_total_size) return IntegrityError.bad_total_size;
    }

    pub fn allocatePages(bootloader_information: *Information, size: u64, alignment: u64, options: PageAllocator.AllocateOptions) Allocator.Allocate.Error!PhysicalMemoryRegion {
        const allocation = blk: {
            if (bootloader_information.stage != .cpu) {
                if (size & lib.arch.page_mask(lib.arch.valid_page_sizes[0]) != 0) return Allocator.Allocate.Error.OutOfMemory;
                if (alignment & lib.arch.page_mask(lib.arch.valid_page_sizes[0]) != 0) return Allocator.Allocate.Error.OutOfMemory;

                const four_kb_pages = @intCast(u32, @divExact(size, lib.arch.valid_page_sizes[0]));

                const entries = bootloader_information.getMemoryMapEntries();
                const page_counters = bootloader_information.getPageCounters();

                for (entries, 0..) |entry, entry_index| {
                    const busy_size = @as(u64, page_counters[entry_index]) * lib.arch.valid_page_sizes[0];
                    const size_left = entry.region.size - busy_size;
                    const target_address = entry.region.address.offset(busy_size);

                    if (entry.type == .usable and target_address.value() <= lib.maxInt(usize) and size_left > size and entry.region.address.value() != 0) {
                        if (entry.region.address.isAligned(alignment)) {
                            const result = PhysicalMemoryRegion{
                                .address = target_address,
                                .size = size,
                            };

                            lib.zero(@intToPtr([*]u8, lib.safeArchitectureCast(result.address.value()))[0..lib.safeArchitectureCast(result.size)]);

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
                            const aligned_address = lib.alignForwardGeneric(u64, target_address.value(), alignment);
                            const difference = aligned_address - target_address.value();
                            const allowed_quota = alignment / options.space_waste_allowed_to_guarantee_alignment;

                            if (aligned_address + size < entry.region.address.offset(entry.region.size).value() and difference <= allowed_quota) {
                                const result = PhysicalMemoryRegion{
                                    .address = PhysicalAddress.new(aligned_address),
                                    .size = size,
                                };

                                lib.zero(@intToPtr([*]u8, lib.safeArchitectureCast(result.address.value()))[0..lib.safeArchitectureCast(result.size)]);
                                page_counters[entry_index] += @intCast(u32, difference + size) >> lib.arch.page_shifter(lib.arch.valid_page_sizes[0]);

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
        const bootloader_information = @ptrCast(*Information, @alignCast(@alignOf(Information), context));
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
            const size_to_page_allocate = lib.alignForwardGeneric(u64, size, lib.arch.valid_page_sizes[0]);
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

    pub fn fetchFileByType(bootloader_information: *Information, file_type: File.Type) ?[]const u8 {
        const files = bootloader_information.getFiles();
        for (files) |file_descriptor| {
            if (file_descriptor.type == file_type) {
                return file_descriptor.getContent(bootloader_information);
            }
        }

        return null;
    }

    pub fn initializeVirtualAddressSpace(bootloader_information: *Information) !paging.Specific {
        return try privileged.arch.paging.initKernelBSP(bootloader_information);
    }
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

    comptime {
        assert(@sizeOf(MemoryMapEntry) == @sizeOf(u64) * 3);
    }
};

pub const File = extern struct {
    content_offset: u32,
    content_size: u32,
    path_offset: u32,
    path_size: u32,
    type: Type,
    reserved: u32 = 0,

    pub fn getContent(file: File, bootloader_information: *Information) []align(0x200) const u8 {
        return file.getContentSlice(bootloader_information);
    }

    inline fn getContentSlice(file: File, bootloader_information: *Information) []align(0x200) u8 {
        const content_slice_offset = bootloader_information.getSliceOffset(.file_contents);
        return @intToPtr([*]align(0x200) u8, @ptrToInt(bootloader_information) + content_slice_offset.offset + file.content_offset)[0..file.content_size];
    }

    pub fn copyContent(file: File, bootloader_information: *Information, src_slice: []const u8) void {
        const dst_slice = file.getContentSlice(bootloader_information);
        lib.log.debug("Destination slice: {}. Source slice: {}", .{ dst_slice.len, src_slice.len });
        lib.copy(u8, dst_slice, src_slice);
    }

    pub fn getPath(file: File, bootloader_information: *Information) []const u8 {
        const content_slice_offset = bootloader_information.getSliceOffset(.file_names);
        return @intToPtr([*]const u8, @ptrToInt(bootloader_information) + content_slice_offset.offset + file.path_offset)[0..file.path_size];
    }

    pub const Type = enum(u32) {
        cpu,
        font,
        init,
    };
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
            total_size = lib.alignForwardGeneric(u32, total_size, tuple.alignment);
            total_size += lib.alignForwardGeneric(u32, size, tuple.alignment);
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
            const size = lib.alignForwardGeneric(u32, tuple.size, tuple.alignment);

            allocated_size = lib.alignForwardGeneric(u32, allocated_size, tuple.alignment);
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
        return lib.alignForwardGeneric(u32, tuples.total_size, lib.arch.valid_page_sizes[0]);
    }
};

pub const Font = extern struct {
    file: PhysicalMemoryRegion align(8), // so 32-bit doesn't whine
    glyph_buffer_size: u32,
    character_size: u8,
    draw: *const fn (font: *const Font, framebuffer: *const Framebuffer, character: u8, color: u32, offset_x: u32, offset_y: u32) void,

    pub fn fromPSF1(file: []const u8) !Font {
        const header = @ptrCast(*const lib.PSF1.Header, file.ptr);
        if (!lib.equal(u8, &header.magic, &lib.PSF1.Header.magic)) {
            return lib.PSF1.Error.invalid_magic;
        }

        const glyph_buffer_size = @as(u32, header.character_size) * (lib.maxInt(u8) + 1) * (1 + @boolToInt(header.mode == 1));

        return .{
            .file = PhysicalMemoryRegion.new(PhysicalAddress.new(@ptrToInt(file.ptr)), file.len),
            .glyph_buffer_size = glyph_buffer_size,
            .character_size = header.character_size,
            .draw = drawPSF1,
        };
    }

    fn drawPSF1(font: *const Font, framebuffer: *const Framebuffer, character: u8, color: u32, offset_x: u32, offset_y: u32) void {
        const bootloader_information = @fieldParentPtr(Information, "framebuffer", framebuffer);
        const glyph_buffer_virtual_region = if (bootloader_information.stage == .trampoline) font.file.toHigherHalfVirtualAddress() else font.file.toIdentityMappedVirtualAddress();
        const glyph_buffer = glyph_buffer_virtual_region.access(u8)[@sizeOf(lib.PSF1.Header)..][0..font.glyph_buffer_size];
        const glyph_offset = @as(usize, character) * font.character_size;
        const glyph = glyph_buffer[glyph_offset .. glyph_offset + font.character_size];

        var glyph_index: usize = 0;
        _ = glyph_index;

        const pixels_per_scanline = @divExact(framebuffer.pitch, @divExact(framebuffer.bpp, @bitSizeOf(u8)));
        const fb = @intToPtr([*]u32, framebuffer.address)[0 .. pixels_per_scanline * framebuffer.height];
        var y = offset_y;

        for (glyph) |byte| {
            const base_index = y * pixels_per_scanline + offset_x;
            if (byte & 1 << 7 != 0) fb[base_index + 0] = color;
            if (byte & 1 << 6 != 0) fb[base_index + 1] = color;
            if (byte & 1 << 5 != 0) fb[base_index + 2] = color;
            if (byte & 1 << 4 != 0) fb[base_index + 3] = color;
            if (byte & 1 << 3 != 0) fb[base_index + 4] = color;
            if (byte & 1 << 2 != 0) fb[base_index + 5] = color;
            if (byte & 1 << 1 != 0) fb[base_index + 6] = color;
            if (byte & 1 << 0 != 0) fb[base_index + 7] = color;

            y += 1;
        }
    }
};

pub const DrawContext = extern struct {
    x: u32 = 0,
    y: u32 = 0,
    color: u32 = 0xff_ff_ff_ff,
    reserved: u32 = 0,

    pub const Error = error{};
    pub const Writer = lib.Writer(*DrawContext, DrawContext.Error, DrawContext.write);

    pub fn write(draw_context: *DrawContext, bytes: []const u8) DrawContext.Error!usize {
        const bootloader_information = @fieldParentPtr(Information, "draw_context", draw_context);
        const color = draw_context.color;
        for (bytes) |byte| {
            if (byte != '\n') {
                bootloader_information.font.draw(&bootloader_information.font, &bootloader_information.framebuffer, byte, color, draw_context.x, draw_context.y);
                if (draw_context.x + 8 < bootloader_information.framebuffer.width) {
                    draw_context.x += @bitSizeOf(u8);
                    continue;
                }
            }

            if (draw_context.y < bootloader_information.framebuffer.width) {
                draw_context.y += bootloader_information.font.character_size;
                draw_context.x = 0;
            } else {
                asm volatile (
                    \\cli
                    \\hlt
                );
            }
        }

        return bytes.len;
    }

    pub inline fn clearScreen(draw_context: *DrawContext, color: u32) void {
        const bootloader_information = @fieldParentPtr(Information, "draw_context", draw_context);
        const pixels_per_scanline = @divExact(bootloader_information.framebuffer.pitch, @divExact(bootloader_information.framebuffer.bpp, @bitSizeOf(u8)));
        const framebuffer_pixels = @intToPtr([*]u32, bootloader_information.framebuffer.address)[0 .. pixels_per_scanline * bootloader_information.framebuffer.height];
        var y: u32 = 0;
        while (y < bootloader_information.framebuffer.height) : (y += 1) {
            const line = framebuffer_pixels[y * pixels_per_scanline .. y * pixels_per_scanline + pixels_per_scanline];
            for (line) |*pixel| {
                pixel.* = color;
            }
        }
    }
};

pub const Stage = enum(u32) {
    early = 0,
    only_graphics = 1,
    trampoline = 2,
    cpu = 3,
};
