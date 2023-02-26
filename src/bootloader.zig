pub const BIOS = @import("bootloader/bios.zig");
pub const UEFI = @import("bootloader/uefi.zig");
pub const limine = @import("bootloader/limine/limine.zig");
pub const arch = @import("bootloader/arch.zig");

const lib = @import("lib");
const assert = lib.assert;
const Allocator = lib.Allocator;
pub const Protocol = lib.Bootloader.Protocol;

const privileged = @import("privileged");
const ACPI = privileged.ACPI;
const AddressInterface = privileged.Address.Interface(u64);
const PhysicalAddress = AddressInterface.PhysicalAddress;
const VirtualAddress = AddressInterface.VirtualAddress;
const PhysicalMemoryRegion = AddressInterface.PhysicalMemoryRegion;
const VirtualMemoryRegion = AddressInterface.VirtualMemoryRegion;
pub const VirtualAddressSpace = privileged.Address.Interface(u64).VirtualAddressSpace(switch (lib.cpu.arch) {
    .x86 => .x86_64,
    else => lib.cpu.arch,
});

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

pub const Information = extern struct {
    entry_point: u64,
    higher_half: u64,
    total_size: u32,
    version: Version,
    protocol: lib.Bootloader.Protocol,
    bootloader: lib.Bootloader,
    stage: Stage,
    page_allocator: Allocator = .{
        .callbacks = .{
            .allocate = pageAllocate,
        },
    },
    configuration: packed struct(u32) {
        memory_map_diff: u8,
        reserved: u24 = 0,
    },
    heap: Heap,
    cpu_driver_mappings: CPUDriverMappings,
    framebuffer: Framebuffer,
    draw_context: DrawContext,
    font: Font,
    smp: SMP.Information,
    virtual_address_space: VirtualAddressSpace,
    architecture: Architecture,
    slices: lib.EnumStruct(Slice.Name, Slice),

    pub const Architecture = switch (lib.cpu.arch) {
        .x86, .x86_64 => extern struct {
            rsdp_address: u64,
            gdt: privileged.arch.x86_64.GDT.Table = .{},
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
            cpu_driver_stack,
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
            arr[@enumToInt(Slice.Name.cpu_driver_stack)] = u8;
            arr[@enumToInt(Slice.Name.memory_map_entries)] = MemoryMapEntry;
            arr[@enumToInt(Slice.Name.page_counters)] = u32;
            arr[@enumToInt(Slice.Name.smps)] = SMP;
            break :blk arr;
        };

        pub fn dereference(slice: Slice, comptime slice_name: Slice.Name, bootloader_information: *const Information) []Slice.TypeMap[@enumToInt(slice_name)] {
            const Type = Slice.TypeMap[@enumToInt(slice_name)];
            const address = @ptrToInt(bootloader_information) + slice.offset;
            return @intToPtr([*]Type, address)[0..slice.len];
        }
    };

    // TODO:
    const PA = PhysicalAddress(.global);
    const PMR = PhysicalMemoryRegion(.global);

    const Heap = extern struct {
        allocator: Allocator = .{
            .callbacks = .{
                .allocate = heapAllocate,
            },
        },
        regions: [6]PMR = lib.zeroes([6]PMR),
    };

    pub const SMP = extern struct {
        acpi_id: u32,
        lapic_id: u32,
        entry_point: u64,
        argument: u64,

        pub const Information = extern struct {
            cpu_count: u32,
            bsp_lapic_id: u32,
        };

        pub const Trampoline = extern struct {
            address: u32,

            comptime {
                assert(lib.cpu.arch == .x86 or lib.cpu.arch == .x86_64);
            }

            pub const Argument = extern struct {
                hhdm: u64 align(8),
                cr3: u32,
                reserved: u16 = 0,
                gdt_descriptor: privileged.arch.x86_64.GDT.Descriptor,

                comptime {
                    assert(@sizeOf(Argument) == 24);
                }
            };
        };
    };

    pub fn initializeSMP(bootloader_information: *Information, madt: *const ACPI.MADT) void {
        if (bootloader_information.bootloader != .rise) @panic("Protocol not supported");

        const smp_records = bootloader_information.getSlice(.smps);

        switch (lib.cpu.arch) {
            .x86, .x86_64 => {
                const cr3 = bootloader_information.virtual_address_space.arch.cr3;
                if (@bitCast(u64, cr3) > lib.maxInt(u32)) {
                    @panic("CR3 overflow");
                }
                const lapicWrite = privileged.arch.x86_64.APIC.write;

                var iterator = madt.getIterator();
                var smp_index: usize = 0;

                const smp_trampoline_physical_address = PhysicalAddress(.local).new(@ptrToInt(&arch.x86_64.smp_trampoline));
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

                                    privileged.arch.x86_64.paging.setMappingFlags(&bootloader_information.virtual_address_space, .global, smp_trampoline_buffer_region.address, .{
                                        .write = true,
                                        .execute = true,
                                        .global = true,
                                    }) catch @panic("can't set smp trampoline flags");

                                    const smp_trampoline_buffer = smp_trampoline_buffer_region.access(u8);
                                    const smp_trampoline_region = PhysicalMemoryRegion(.local).new(smp_trampoline_physical_address, smp_trampoline_size);
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
                    .gdt_descriptor = bootloader_information.architecture.gdt.getDescriptor(),
                };

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
                        else => {},
                    }
                }

                lib.log.debug("Enabled all cores!", .{});
            },
            else => @compileError("Architecture not supported"),
        }
    }

    pub fn getAlignedTotalSize(information: *Information) u32 {
        assert(information.total_size > 0);
        return lib.alignForwardGeneric(u32, information.total_size, lib.arch.valid_page_sizes[0]);
    }

    pub fn getFiles(information: *Information) []File {
        const files_slice_struct = information.slices.fields.files;
        const files = @intToPtr([*]File, @ptrToInt(information) + files_slice_struct.offset)[0..files_slice_struct.len];
        return files;
    }

    pub fn getSliceOffset(information: *const Information, comptime offset_name: Slice.Name) Slice {
        const slice_offset = information.slices.array.values[@enumToInt(offset_name)];
        return slice_offset;
    }

    pub fn getSlice(information: *const Information, comptime offset_name: Slice.Name) []Slice.TypeMap[@enumToInt(offset_name)] {
        const slice_offset = information.slices.array.values[@enumToInt(offset_name)];
        return slice_offset.dereference(offset_name, information);
    }

    pub inline fn getStackTop(information: *const Information) usize {
        const stack_slice = information.getSlice(.cpu_driver_stack);
        return @ptrToInt(stack_slice.ptr) + stack_slice.len;
    }

    pub fn getStackSliceOffset() comptime_int {
        return @offsetOf(Information, "slices") + (@as(comptime_int, @enumToInt(Slice.Name.cpu_driver_stack)) * @sizeOf(Slice));
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
    };
    // TODO: further checks
    pub fn checkIntegrity(information: *const Information) !void {
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

    pub fn pageAllocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
        const bootloader_information = @fieldParentPtr(Information, "page_allocator", allocator);

        if (size & lib.arch.page_mask(lib.arch.valid_page_sizes[0]) != 0) return Allocator.Allocate.Error.OutOfMemory;
        if (alignment & lib.arch.page_mask(lib.arch.valid_page_sizes[0]) != 0) return Allocator.Allocate.Error.OutOfMemory;
        const four_kb_pages = @intCast(u32, @divExact(size, lib.arch.valid_page_sizes[0]));

        const entries = bootloader_information.getMemoryMapEntries();
        const page_counters = bootloader_information.getPageCounters();

        for (entries, 0..) |entry, entry_index| {
            const busy_size = page_counters[entry_index] * lib.arch.valid_page_sizes[0];
            const size_left = entry.region.size - busy_size;
            if (entry.type == .usable and size_left > size and entry.region.address.value() != 0) {
                if (entry.region.address.isAligned(alignment)) {
                    const result = Allocator.Allocate.Result{
                        .address = entry.region.address.offset(busy_size).value(),
                        .size = size,
                    };

                    lib.zero(@intToPtr([*]u8, lib.safeArchitectureCast(result.address))[0..lib.safeArchitectureCast(result.size)]);

                    //lib.log.debug("Allocating 0x{x}-0x{x}", .{ result.address, result.address + result.size });

                    page_counters[entry_index] += four_kb_pages;

                    return result;
                }
            }
        }

        return Allocator.Allocate.Error.OutOfMemory;
    }

    pub fn heapAllocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
        const bootloader_information = @fieldParentPtr(Information, "heap", @fieldParentPtr(Heap, "allocator", allocator));
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
                    .address = PA.new(allocated_region.address),
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
        @panic("todo: heap allocate");
    }
};

pub const CPUDriverMappings = extern struct {
    text: Mapping = .{},
    data: Mapping = .{},
    rodata: Mapping = .{},

    const Mapping = extern struct {
        physical: PhysicalAddress(.local) = PhysicalAddress(.local).invalid(),
        virtual: VirtualAddress(.local) = .null,
        size: u64 = 0,
        flags: privileged.arch.VirtualAddressSpace.Flags = .{},
        reserved: u32 = 0,
    };
};

pub const MemoryMapEntry = extern struct {
    region: PhysicalMemoryRegion(.global) align(8),
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

    pub fn getContent(file: File, bootloader_information: *Information) []const u8 {
        return @intToPtr([*]const u8, @ptrToInt(bootloader_information) + file.content_offset)[0..file.content_size];
    }

    pub const Type = enum(u32) {
        cpu_driver,
        font,
    };

    pub const Parser = struct {
        text: []const u8,
        index: u32 = 0,

        pub fn init(text: []const u8) File.Parser {
            return .{
                .text = text,
            };
        }

        const Error = error{
            err,
        };

        pub const Unit = struct {
            host_path: []const u8,
            host_base: []const u8,
            suffix_type: SuffixType,
            guest: []const u8,
            type: File.Type,
        };

        pub const SuffixType = enum {
            none,
            arch,
            full,
        };

        pub fn next(parser: *File.Parser) !?Unit {
            // Do this to avoid getting the editor crazy about it
            const left_curly_brace = 0x7b;
            const right_curly_brace = 0x7d;

            while (parser.index < parser.text.len and parser.text[parser.index] != right_curly_brace) {
                try parser.expectChar('.');
                try parser.expectChar(left_curly_brace);

                if (parser.index < parser.text.len and parser.text[parser.index] != right_curly_brace) {
                    const host_path_field = try parser.parseField("host_path");
                    const host_base_field = try parser.parseField("host_base");
                    const suffix_type = lib.stringToEnum(SuffixType, try parser.parseField("suffix_type")) orelse return Error.err;
                    const guest_field = try parser.parseField("guest");
                    const file_type = lib.stringToEnum(File.Type, try parser.parseField("type")) orelse return Error.err;
                    try parser.expectChar(right_curly_brace);
                    parser.maybeExpectChar(',');
                    parser.skipSpace();

                    return .{
                        .host_path = host_path_field,
                        .host_base = host_base_field,
                        .suffix_type = suffix_type,
                        .guest = guest_field,
                        .type = file_type,
                    };
                } else {
                    @panic("WTF");
                }
            }

            return null;
        }

        inline fn consume(parser: *File.Parser) void {
            parser.index += 1;
        }

        fn parseField(parser: *File.Parser, field: []const u8) ![]const u8 {
            try parser.expectChar('.');
            try parser.expectString(field);
            try parser.expectChar('=');
            const field_value = try parser.expectQuotedString();
            parser.maybeExpectChar(',');

            return field_value;
        }

        fn skipSpace(parser: *File.Parser) void {
            while (parser.index < parser.text.len) {
                const char = parser.text[parser.index];
                const is_space = char == ' ' or char == '\n' or char == '\r' or char == '\t';
                if (!is_space) break;
                parser.consume();
            }
        }

        fn maybeExpectChar(parser: *File.Parser, char: u8) void {
            parser.skipSpace();
            if (parser.text[parser.index] == char) {
                parser.consume();
            }
        }

        fn expectChar(parser: *File.Parser, expected_char: u8) !void {
            parser.skipSpace();
            const char = parser.text[parser.index];
            if (char != expected_char) {
                return Error.err;
            }

            parser.consume();
        }

        fn expectString(parser: *File.Parser, string: []const u8) !void {
            parser.skipSpace();
            if (!lib.equal(u8, parser.text[parser.index..][0..string.len], string)) {
                return Error.err;
            }

            for (string, 0..) |_, index| {
                _ = index;
                parser.consume();
            }
        }

        fn expectQuotedString(parser: *File.Parser) ![]const u8 {
            parser.skipSpace();
            try parser.expectChar('"');
            const start_index = parser.index;
            while (parser.index < parser.text.len and parser.text[parser.index] != '"') {
                parser.consume();
            }
            const end_index = parser.index;
            try parser.expectChar('"');

            const string = parser.text[start_index..end_index];
            return string;
        }
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
        assert(tuples.total_size > 0);
        return lib.alignForwardGeneric(u32, tuples.total_size, lib.arch.valid_page_sizes[0]);
    }
};

pub const Font = extern struct {
    file: PhysicalMemoryRegion(.local),
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
            .file = PhysicalMemoryRegion(.local).new(PhysicalAddress(.local).new(@ptrToInt(file.ptr)), file.len),
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
};
