const lib = @import("lib");
const assert = lib.assert;
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
const PhysicalAddress = privileged.arch.PhysicalAddress;
const PhysicalMemoryRegion = privileged.arch.PhysicalMemoryRegion;
const VirtualAddress = privileged.arch.VirtualAddress;
const VirtualAddressSpace = privileged.arch.VirtualAddressSpace;
const VirtualMemoryRegion = privileged.arch.VirtualMemoryRegion;
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
pub const panic = UEFI.zigPanic;
pub var draw_writer: bootloader.DrawContext.Writer = undefined;

pub var maybe_bootloader_information: ?*bootloader.Information = null;

pub fn main() noreturn {
    const system_table = UEFI.get_system_table();
    const handle = UEFI.get_handle();
    const boot_services = system_table.boot_services orelse @panic("boot services");
    const out = system_table.con_out orelse @panic("con out");
    UEFI.result(@src(), out.reset(true));
    UEFI.result(@src(), out.clearScreen());
    writer.writeByte('\n') catch unreachable;

    log.debug("EFI revision: 0x{x}", .{system_table.hdr.revision});

    const configuration_tables = system_table.configuration_table[0..system_table.number_of_table_entries];
    const rsdp_physical_address = blk: {
        for (configuration_tables) |configuration_table| {
            if (configuration_table.vendor_guid.eql(ConfigurationTable.acpi_20_table_guid)) {
                break :blk PhysicalAddress(.global).new(@ptrToInt(configuration_table.vendor_table));
            }
        }

        @panic("Unable to find RSDP");
    };

    const cpu_count = blk: {
        const rsdp_descriptor = rsdp_physical_address.toIdentityMappedVirtualAddress().access(*ACPI.RSDP.Descriptor1);
        const madt_header = rsdp_descriptor.findTable(.APIC) orelse @panic("Can't find MADT");
        const madt = @fieldParentPtr(ACPI.MADT, "header", madt_header);
        break :blk madt.getCPUCount();
    };

    framebuffer = blk: {
        const gop = Protocol.locate(UEFI.GraphicsOutputProtocol, boot_services) catch @panic("Can't locate GOP");
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

        const fb = bootloader.Framebuffer{
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
        log.debug("Width: {}. Height: {}. Pixels per scanline: {}. BPP: {}. Pitch: {}", .{ fb.width, fb.height, gop.mode.info.pixels_per_scan_line, pixel_format_info.bpp, fb.pitch });
        break :blk fb;
    };

    const filesystem_root = blk: {
        const loaded_image = Protocol.open(LoadedImageProtocol, boot_services, handle);
        const filesystem_protocol = Protocol.open(SimpleFilesystemProtocol, boot_services, loaded_image.device_handle orelse unreachable);
        var root: *FileProtocol = undefined;
        UEFI.result(@src(), filesystem_protocol.openVolume(&root));
        break :blk root;
    };

    var file_list_file = UEFI.File.get(filesystem_root, "files") catch @panic("Can't read file list");
    var file_list_buffer: [512]u8 = undefined;
    const file_list = file_list_file.read(&file_list_buffer);
    var file_parser = bootloader.File.Parser.init(file_list);
    const cpu_driver_file_index = blk: {
        var maybe_cpu_driver_file_index: ?u32 = null;
        while (file_parser.next() catch @panic("parser error")) |file_descriptor| {
            if (file_count == files.len) @panic("max files");
            const filename = file_descriptor.guest[1..];

            if (file_descriptor.type == .cpu_driver) {
                if (maybe_cpu_driver_file_index != null) @panic("Two cpu drivers");
                maybe_cpu_driver_file_index = file_count;
            }

            files[file_count] = .{
                .type = file_descriptor.type,
                .path = filename,
                .uefi = UEFI.File.get(filesystem_root, filename) catch @panic("Can't get file"),
            };

            file_count += 1;
        }

        break :blk maybe_cpu_driver_file_index orelse @panic("No CPU driver specified in the configuration");
    };

    const total_file_size = blk: {
        var total: u32 = 0;
        for (files[0..file_count]) |file| {
            total += lib.alignForwardGeneric(u32, file.uefi.size, lib.arch.valid_page_sizes[0]);
        }
        break :blk total;
    };

    const total_file_name_size = blk: {
        var total: u32 = 0;
        for (files[0..file_count]) |file| {
            total += @intCast(u32, file.path.len);
        }
        break :blk total;
    };

    const memory_map_entry_count = blk: {
        _ = boot_services.getMemoryMap(&memory_map_size, null, &memory_map_key, &memory_map_descriptor_size, &memory_map_descriptor_version);
        break :blk @intCast(u32, @divExact(memory_map_size, memory_map_descriptor_size) + 1);
    };

    memory_map_size += memory_map_descriptor_size;

    const stack_size = privileged.default_stack_size;
    const length_size_tuples = bootloader.LengthSizeTuples.new(.{
        .bootloader_information = .{
            .length = 1,
            .alignment = lib.arch.valid_page_sizes[0],
        },
        .file_contents = .{
            .length = total_file_size,
            .alignment = lib.arch.valid_page_sizes[0],
        },
        .file_names = .{
            .length = total_file_name_size,
            .alignment = 8,
        },
        .files = .{
            .length = file_count,
            .alignment = @alignOf(bootloader.File),
        },
        .cpu_driver_stack = .{
            .length = stack_size,
            .alignment = lib.arch.valid_page_sizes[0],
        },
        .memory_map_entries = .{
            .length = memory_map_entry_count,
            .alignment = @alignOf(bootloader.MemoryMapEntry),
        },
        .page_counters = .{
            .length = memory_map_entry_count,
            .alignment = @alignOf(u32),
        },
        .cpus = .{
            .length = cpu_count,
            .alignment = 8,
        },
    });

    const bootstrap_memory = blk: {
        log.debug("Expected size: {}. Actual size: {}. Descriptor version: {}", .{ memory_map_descriptor_size, @sizeOf(MemoryDescriptor), memory_map_descriptor_version });

        var memory: []align(UEFI.page_size) u8 = undefined;
        UEFI.result(@src(), boot_services.allocatePages(.AllocateAnyPages, .LoaderData, length_size_tuples.getAlignedTotalSize() >> UEFI.page_shifter, &memory.ptr));
        memory.len = length_size_tuples.getAlignedTotalSize();
        lib.zero(memory);
        break :blk memory;
    };

    const bootloader_information = @ptrCast(*bootloader.Information, bootstrap_memory.ptr);
    maybe_bootloader_information = bootloader_information;
    bootloader_information.* = .{
        .entry_point = 0,
        .higher_half = lib.config.cpu_driver_higher_half_address,
        .total_size = length_size_tuples.total_size,
        .version = .{ .major = 0, .minor = 1, .patch = 0 },
        .protocol = .uefi,
        .bootloader = .rise,
        .stage = .early,
        .configuration = .{ .memory_map_diff = 0 },
        .heap = .{},
        .cpu_driver_mappings = .{},
        .framebuffer = framebuffer,
        .draw_context = .{},
        .font = undefined,
        .virtual_address_space = .{ .arch = .{} },
        .architecture = switch (lib.cpu.arch) {
            .x86_64 => .{ .rsdp_address = rsdp_physical_address.value() },
            else => @compileError("Architecture not supported"),
        },
        .slices = length_size_tuples.createSlices(),
    };

    for (bootloader_information.getSlice(.page_counters)) |*page_counter| {
        page_counter.* = 0;
    }

    const file_contents_slice = bootloader_information.slices.fields.file_contents;
    const file_content_buffer = @intToPtr([*]u8, @ptrToInt(bootloader_information) + file_contents_slice.offset)[0..file_contents_slice.size];
    const file_names_slice = bootloader_information.slices.fields.file_names;
    const file_name_buffer = @intToPtr([*]u8, @ptrToInt(bootloader_information) + file_names_slice.offset)[0..file_names_slice.size];
    const files_slice = bootloader_information.getFiles();
    var name_offset: u32 = 0;
    var content_offset: u32 = 0;

    for (files[0..file_count]) |file, file_index| {
        const file_content = file.uefi.read(file_content_buffer[content_offset .. content_offset + file.uefi.size]);
        _ = file_content;
        const file_name = file.path;
        const file_slice = &files_slice[file_index];
        file_slice.* = .{
            .content_offset = content_offset + file_contents_slice.offset,
            .content_size = file.uefi.size,
            .path_offset = name_offset + file_names_slice.offset,
            .path_size = @intCast(u32, file_name.len),
            .type = file.type,
        };
        lib.copy(u8, file_name_buffer[name_offset .. name_offset + file_name.len], file_name);
        name_offset += @intCast(u32, file_name.len);
        content_offset += lib.alignForwardGeneric(u32, file.uefi.size, lib.arch.valid_page_sizes[0]);
    }

    const expected_memory_map_descriptor_size = memory_map_descriptor_size;
    const expected_memory_map_descriptor_version = memory_map_descriptor_version;
    const expected_memory_map_size = memory_map_size;

    log.debug("Getting memory map before exiting boot services...", .{});

    // Get the debugging font since we actually can't use UEFI logging here
    bootloader_information.font = blk: {
        const font_file = for (bootloader_information.getFiles()) |file| {
            if (file.type == .font) break file.getContent(bootloader_information);
        } else @panic("No debugging font found");

        break :blk bootloader.Font.fromPSF1(font_file) catch @panic("Can't load font");
    };
    draw_writer = .{
        .context = &bootloader_information.draw_context,
    };
    bootloader_information.draw_context.clearScreen(0);
    bootloader_information.stage = .only_graphics;

    UEFI.result(@src(), boot_services.getMemoryMap(&memory_map_size, @ptrCast([*]MemoryDescriptor, &memory_map.buffer), &memory_map_key, &memory_map_descriptor_size, &memory_map_descriptor_version));
    if (expected_memory_map_size != memory_map_size) {
        log.debug("Old memory map size: {}. New memory map size: {}", .{ expected_memory_map_size, memory_map_size });
    }
    if (expected_memory_map_descriptor_size != memory_map_descriptor_size) {
        @panic("Descriptor size change");
    }
    if (expected_memory_map_descriptor_version != memory_map_descriptor_version) {
        @panic("Descriptor size change");
    }
    const real_memory_map_entry_count = @divExact(memory_map_size, memory_map_descriptor_size);
    log.debug("Real: {}. Mine: {}", .{ real_memory_map_entry_count, memory_map_entry_count });
    const diff = @intCast(i16, memory_map_entry_count) - @intCast(i16, real_memory_map_entry_count);
    if (diff < 0) {
        @panic("Memory map entry count diff < 0");
    }

    bootloader_information.configuration.memory_map_diff = @intCast(u8, diff);

    log.debug("Exiting boot services...", .{});
    UEFI.result(@src(), boot_services.exitBootServices(handle, memory_map_key));

    memory_map.reset();

    var entry_index: usize = 0;
    const memory_map_entries = bootloader_information.getMemoryMapEntries();
    while (memory_map.next()) |entry| : (entry_index += 1) {
        memory_map_entries[entry_index] = .{
            .region = PhysicalMemoryRegion(.global).new(PhysicalAddress(.global).new(entry.physical_start), entry.number_of_pages << UEFI.page_shifter),
            .type = switch (entry.type) {
                .ReservedMemoryType, .LoaderCode, .LoaderData, .BootServicesCode, .BootServicesData, .RuntimeServicesCode, .RuntimeServicesData, .ACPIReclaimMemory, .ACPIMemoryNVS, .MemoryMappedIO, .MemoryMappedIOPortSpace, .PalCode, .PersistentMemory => .reserved,
                .ConventionalMemory => .usable,
                .UnusableMemory => .bad_memory,
                else => @panic("Unknown type"),
            },
        };
    }

    bootloader_information.virtual_address_space = blk: {
        const chunk_allocation = bootloader_information.page_allocator.allocateBytes(VirtualAddressSpace.needed_physical_memory_for_bootstrapping_cpu_driver_address_space, UEFI.page_size) catch @panic("Unable to get physical memory to bootstrap CPU driver address space");
        const cpu_driver_address_space_physical_region = PhysicalMemoryRegion(.local){
            .address = PhysicalAddress(.local).new(chunk_allocation.address),
            .size = chunk_allocation.size,
        };
        break :blk VirtualAddressSpace.kernelBSP(cpu_driver_address_space_physical_region);
    };

    const cpu_driver_file_offset = files_slice[cpu_driver_file_index].content_offset;
    const cpu_driver_file_size = files_slice[cpu_driver_file_index].content_size;
    const cpu_driver_executable = @intToPtr([*]const u8, @ptrToInt(bootloader_information) + cpu_driver_file_offset)[0..cpu_driver_file_size];
    var elf_parser = ELF.Parser.init(cpu_driver_executable) catch |err| UEFI.panic("Failed to initialize ELF parser: {}", .{err});

    const program_headers = elf_parser.getProgramHeaders();
    bootloader_information.entry_point = elf_parser.getEntryPoint();

    var segment_count: u32 = 0;
    for (program_headers) |*ph| {
        switch (ph.type) {
            .load => {
                if (ph.size_in_memory == 0) continue;
                if (segment_count == 3) @panic("Exceeded segments");

                log.debug("Checking for PT_LOAD segment...", .{});

                const address_misalignment = ph.virtual_address & (UEFI.page_size - 1);

                if (address_misalignment != 0) {
                    @panic("ELF PH segment size is supposed to be page-aligned");
                }

                if (!lib.isAligned(ph.offset, UEFI.page_size)) {
                    @panic("ELF PH offset is supposed to be page-aligned");
                }

                if (!ph.flags.readable) {
                    @panic("ELF program segment is marked as non-readable");
                }

                if (ph.size_in_file != ph.size_in_memory) {
                    @panic("ELF program segment file size is smaller than memory size");
                }

                const segment_index = segment_count;
                _ = segment_index;
                segment_count += 1;
                const virtual_address_value = ph.virtual_address & 0xffff_ffff_ffff_f000;
                const aligned_segment_size = @intCast(u32, lib.alignForward(ph.size_in_memory + address_misalignment, UEFI.page_size));
                log.debug("Trying to allocate: 0x{x} bytes for segment", .{aligned_segment_size});
                const segment_allocation = bootloader_information.page_allocator.allocateBytes(aligned_segment_size, UEFI.page_size) catch @panic("segment allocation failed");
                log.debug("Allocated 0x{x} bytes for segment at 0x{x}", .{ segment_allocation.size, segment_allocation.address });
                const physical_address_value = segment_allocation.address;
                const aligned_physical_address = physical_address_value + address_misalignment;
                const dst_slice = @intToPtr([*]u8, aligned_physical_address)[0..ph.size_in_memory];
                const src_slice = cpu_driver_executable[ph.offset..][0..ph.size_in_memory];

                if (!(dst_slice.len >= src_slice.len)) {
                    @panic("WTFFFFFFF");
                }
                assert(dst_slice.len >= src_slice.len);
                lib.copy(u8, dst_slice, src_slice);
                const core_locality: privileged.CoreLocality = switch (ph.flags.writable) {
                    true => .local,
                    false => .global,
                };

                switch (core_locality) {
                    inline else => |locality| {
                        const physical_address = PhysicalAddress(locality).new(physical_address_value);
                        const virtual_address = VirtualAddress(locality).new(virtual_address_value);
                        const size = aligned_segment_size;
                        const flags = .{ .write = ph.flags.writable, .execute = ph.flags.executable };
                        log.debug("trying to map cpu driver section: 0x{x} -> 0x{x}, 0x{x}", .{ physical_address.value(), virtual_address.value(), size });
                        paging.bootstrap_map(&bootloader_information.virtual_address_space, locality, physical_address, virtual_address, size, flags, &bootloader_information.page_allocator) catch |err| UEFI.panic("unable to map program segment: {}", .{err});
                        log.debug("mapped cpu driver section: 0x{x} -> 0x{x}, 0x{x}", .{ physical_address.value(), virtual_address.value(), size });

                        const mapping_ptr =
                            if (ph.flags.writable and !ph.flags.executable)
                            // data section
                            &bootloader_information.cpu_driver_mappings.data
                        else if (!ph.flags.writable and !ph.flags.executable)
                            // rodata
                            &bootloader_information.cpu_driver_mappings.rodata
                        else if (!ph.flags.writable and ph.flags.executable)
                            // text section
                            &bootloader_information.cpu_driver_mappings.text
                        else
                            @panic("unreachable flags");
                        mapping_ptr.physical = physical_address.toLocal();
                        mapping_ptr.virtual = virtual_address.toLocal();
                        mapping_ptr.size = size;
                        mapping_ptr.flags = flags;
                    },
                }
            },
            else => {
                log.warn("Unhandled PH {s}", .{@tagName(ph.type)});
            },
        }
    }

    // Map the trampoline code (part of the UEFI executable).
    // Actually mapping the whole UEFI executable so we don't have random problems with code being dereferenced by the trampoline
    log.debug("Mapping trampoline code...", .{});
    {
        const trampoline_code_start = @ptrToInt(&bootloader.arch.x86_64.trampoline);

        memory_map.reset();
        while (memory_map.next()) |entry| {
            const entry_size = entry.number_of_pages * UEFI.page_size;
            if (entry.physical_start < trampoline_code_start and trampoline_code_start < entry.physical_start + entry_size) {
                log.debug("Entry: 0x{x}-0x{x}", .{ entry.physical_start, entry.physical_start + entry.number_of_pages * UEFI.page_size });

                const code_physical_region = PhysicalMemoryRegion(.local).new(PhysicalAddress(.local).new(entry.physical_start), entry_size);
                const code_virtual_address = code_physical_region.address.toIdentityMappedVirtualAddress();
                paging.bootstrap_map(&bootloader_information.virtual_address_space, .local, code_physical_region.address, code_virtual_address, code_physical_region.size, .{ .write = false, .execute = true }, &bootloader_information.page_allocator) catch @panic("Unable to map kernel trampoline code");
                break;
            }
        }
    }

    // Map the bootloader information
    log.debug("Mapping bootloader information...", .{});
    {
        const physical_address = PhysicalAddress(.local).new(@ptrToInt(bootloader_information));
        const size = bootloader_information.getAlignedTotalSize();
        paging.bootstrap_map(&bootloader_information.virtual_address_space, .local, physical_address, physical_address.toIdentityMappedVirtualAddress(), size, .{ .write = true, .execute = false }, &bootloader_information.page_allocator) catch |err| UEFI.panic("Unable to map bootloader information (identity): {}", .{err});
        paging.bootstrap_map(&bootloader_information.virtual_address_space, .local, physical_address, physical_address.toHigherHalfVirtualAddress(), size, .{ .write = true, .execute = false }, &bootloader_information.page_allocator) catch |err| UEFI.panic("Unable to map bootloader information (higher half): {}", .{err});
    }

    // Map all usable memory to avoid kernel delays later
    // TODO:
    // 1. Divide memory per CPU to avoid shared memory
    // 2. User manager
    log.debug("Mapping usable memory...", .{});
    memory_map.reset();
    while (memory_map.next()) |entry| {
        if (entry.type == .ConventionalMemory) {
            const physical_address = PhysicalAddress(.local).new(entry.physical_start);
            const virtual_address = physical_address.toIdentityMappedVirtualAddress();
            const size = entry.number_of_pages * lib.arch.valid_page_sizes[0];
            paging.bootstrap_map(&bootloader_information.virtual_address_space, .local, physical_address, virtual_address, size, .{ .write = true, .execute = false }, &bootloader_information.page_allocator) catch @panic("Unable to map page tables");
        }
        //log.debug("entry: {s}. 0x{x}, pages: 0x{x}", .{ @tagName(entry.type), entry.physical_start, entry.number_of_pages });
        if (entry.physical_start <= 0x00000000bfef1f98 and 0x00000000bfef1f98 < entry.physical_start + entry.number_of_pages * UEFI.page_size) {
            log.debug("contained", .{});
        }
    }

    // Hack to map UEFI stack
    log.debug("Mapping UEFI stack...", .{});
    memory_map.reset();
    const rsp = asm volatile (
        \\mov %rsp, %[rsp]
        : [rsp] "=r" (-> u64),
    );
    log.debug("stack: 0x{x}", .{rsp});
    while (memory_map.next()) |entry| {
        const region_size = entry.number_of_pages * UEFI.page_size;
        if (entry.physical_start < rsp and rsp < entry.physical_start + region_size) {
            const rsp_physical_address = PhysicalAddress(.local).new(entry.physical_start);
            const rsp_virtual_address = rsp_physical_address.toIdentityMappedVirtualAddress();
            log.debug("mapping {s} 0x{x} - 0x{x}", .{ @tagName(entry.type), entry.physical_start, entry.physical_start + region_size });
            assert(region_size > 0);
            paging.bootstrap_map(&bootloader_information.virtual_address_space, .local, rsp_physical_address, rsp_virtual_address, region_size, .{ .write = true, .execute = false }, &bootloader_information.page_allocator) catch @panic("Unable to map page tables");
            break;
        }
    }

    // Map framebuffer
    log.debug("Mapping framebuffer...", .{});
    {
        const physical_address = PhysicalAddress(.global).new(bootloader_information.framebuffer.address);
        const virtual_address = physical_address.toIdentityMappedVirtualAddress();
        const size = bootloader_information.framebuffer.getSize();
        paging.bootstrap_map(&bootloader_information.virtual_address_space, .global, physical_address, virtual_address, size, .{ .write = true, .execute = false }, &bootloader_information.page_allocator) catch @panic("Unable to map page tables");
    }

    log.debug("Jumping to trampoline...", .{});
    bootloader.arch.x86_64.trampoline(bootloader_information);
}

pub fn file_to_higher_half(file: []const u8) []const u8 {
    var result = file;
    result.ptr = file.ptr + lib.config.kernel_higher_half_address;
    return result;
}

extern const kernel_trampoline_start: *volatile u8;
extern const kernel_trampoline_end: *volatile u8;

pub const std_options = struct {
    pub const log_level = lib.std.log.Level.debug;

    pub fn logFn(comptime level: lib.std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
        const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
        switch (lib.cpu.arch) {
            .x86_64 => {
                if (maybe_bootloader_information) |bootloader_information| {
                    if (@enumToInt(bootloader_information.stage) < @enumToInt(bootloader.Stage.only_graphics)) {
                        var buffer: [4096]u8 = undefined;
                        const formatted_buffer = lib.std.fmt.bufPrint(buffer[0..], prefix ++ format ++ "\r\n", args) catch unreachable;

                        for (formatted_buffer) |c| {
                            const fake_c = [2]u16{ c, 0 };
                            _ = UEFI.get_system_table().con_out.?.outputString(@ptrCast(*const [1:0]u16, &fake_c));
                        }
                    } else {
                        draw_writer.print(prefix ++ format ++ "\n", args) catch unreachable;
                    }
                }

                writer.print(prefix ++ format ++ "\n", args) catch unreachable;
            },
            else => @compileError("Unsupported CPU architecture"),
        }
    }
};

fn flush_new_line() !void {
    switch (lib.cpu.arch) {
        .x86_64 => {
            if (!config.real_hardware) {
                try writer.writeByte('\n');
            }
        },
        else => @compileError("arch not supported"),
    }
}

const File = struct {
    type: bootloader.File.Type,
    path: []const u8,
    uefi: UEFI.File,
};

var files: [16]File = undefined;
var file_count: u32 = 0;

const practical_memory_map_descriptor_size = 0x30;
const memory_map_descriptor_count = 256;
var memory_map_key: usize = 0;
var memory_map_descriptor_size: usize = 0;
var memory_map_descriptor_version: u32 = 0;
var memory_map_size: usize = 0;
var memory_map = MemoryMap{};

pub const MemoryMap = struct {
    buffer: [practical_memory_map_descriptor_size * memory_map_descriptor_count]u8 align(@alignOf(MemoryDescriptor)) = undefined,
    offset: usize = 0,

    pub fn next(it: *MemoryMap) ?*MemoryDescriptor {
        if (it.offset < memory_map_size) {
            const descriptor = @ptrCast(*MemoryDescriptor, @alignCast(@alignOf(MemoryDescriptor), memory_map.buffer[it.offset..].ptr));
            it.offset += memory_map_descriptor_size;
            return descriptor;
        }

        return null;
    }

    pub inline fn reset(it: *MemoryMap) void {
        it.offset = 0;
    }
};
