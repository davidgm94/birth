const common = @import("common");
const assert = common.assert;
const config = common.config;
const CustomAllocator = common.CustomAllocator;
const ELF = common.ELF;
const logger = common.log.scoped(.UEFI);

const privileged = @import("privileged");
const UEFI = privileged.UEFI;
const BootloaderInformation = UEFI.BootloaderInformation;
const BootServices = UEFI.BootServices;
const ConfigurationTable = UEFI.ConfigurationTable;
const File = UEFI.File;
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

const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const VirtualAddress = privileged.VirtualAddress;
const VirtualAddressSpace = privileged.VirtualAddressSpace;

const arch = @import("arch");
const CPU = arch.CPU;
const GDT = x86_64.GDT;
const page_size = arch.page_size;
const page_shifter = arch.page_shifter;
const VAS = arch.VAS;
const x86_64 = arch.x86_64;

pub fn main() noreturn {
    const system_table = UEFI.get_system_table();
    const handle = UEFI.get_handle();
    const boot_services = system_table.boot_services orelse @panic("boot services");
    const out = system_table.con_out orelse @panic("con out");
    UEFI.result(@src(), out.reset(true));
    UEFI.result(@src(), out.clearScreen());
    flush_new_line() catch unreachable;

    const revision_string = switch (system_table.firmware_revision) {
        SystemTable.revision_1_02 => "1.02",
        SystemTable.revision_1_10 => "1.10",
        SystemTable.revision_2_00 => "2.00",
        SystemTable.revision_2_10 => "2.10",
        SystemTable.revision_2_20 => "2.20",
        SystemTable.revision_2_30 => "2.30",
        SystemTable.revision_2_31 => "2.31",
        SystemTable.revision_2_40 => "2.40",
        SystemTable.revision_2_50 => "2.50",
        SystemTable.revision_2_60 => "2.60",
        SystemTable.revision_2_70 => "2.70",
        SystemTable.revision_2_80 => "2.80",
        else => "Unrecognized EFI version: check that Zig UEFI standard library is up-to-date and, if not, BIOS is corrupted",
    };

    logger.debug("EFI revision: {s}", .{revision_string});

    const configuration_tables = system_table.configuration_table[0..system_table.number_of_table_entries];
    const rsdp_physical_address = blk: {
        for (configuration_tables) |configuration_table| {
            if (configuration_table.vendor_guid.eql(ConfigurationTable.acpi_20_table_guid)) {
                break :blk PhysicalAddress.new(@ptrToInt(configuration_table.vendor_table));
            }
        }

        UEFI.panic("Unable to find RSDP", .{});
    };

    const filesystem_root = blk: {
        const loaded_image = Protocol.open(LoadedImageProtocol, boot_services, handle);
        const filesystem_protocol = Protocol.open(SimpleFilesystemProtocol, boot_services, loaded_image.device_handle orelse unreachable);
        var root: *FileProtocol = undefined;
        UEFI.result(@src(), filesystem_protocol.openVolume(&root));
        break :blk root;
    };

    var kernel_file = File.get(filesystem_root, "kernel.elf");
    var loader_file = File.get(filesystem_root, "uefi_trampoline.bin");
    logger.debug("Got files", .{});

    var memory_map_size = blk: {
        var memory_map_size: usize = 0;
        var memory_map_key: usize = 0;
        var memory_map_descriptor_size: usize = 0;
        var memory_map_descriptor_version: u32 = 0;
        _ = boot_services.getMemoryMap(&memory_map_size, null, &memory_map_key, &memory_map_descriptor_size, &memory_map_descriptor_version);
        logger.debug("Expected size: {}. Actual size: {}", .{ memory_map_descriptor_size, @sizeOf(MemoryDescriptor) });
        break :blk common.align_forward(memory_map_size + page_size, page_size);
    };

    var bootloader_information = BootloaderInformation.new(boot_services, rsdp_physical_address, kernel_file.size, loader_file.size, memory_map_size, page_size << 5);
    logger.debug("Got new bootloader information", .{});

    const kernel_file_content = kernel_file.read(&bootloader_information.memory, .kernel_file);
    const loader_file_content = loader_file.read(&bootloader_information.memory, .loader_file);

    logger.debug("Trying to get memory map", .{});
    var memory_map = @intToPtr([*]MemoryDescriptor, bootloader_information.memory.allocate_aligned(@intCast(u32, memory_map_size), page_size, MemoryCategory.memory_map) catch @panic("can't allocate memory for memory map"));
    var memory_map_key: usize = 0;
    var memory_map_descriptor_size: usize = 0;
    var memory_map_descriptor_version: u32 = 0;
    UEFI.result(@src(), boot_services.getMemoryMap(&memory_map_size, memory_map, &memory_map_key, &memory_map_descriptor_size, &memory_map_descriptor_version));
    assert(memory_map_size % memory_map_descriptor_size == 0);
    logger.debug("Memory map size: {}", .{memory_map_size});

    logger.debug("Exiting boot services...", .{});
    UEFI.result(@src(), boot_services.exitBootServices(handle, memory_map_key));

    var memory_map_i: u64 = 0;
    const memory_map_entry_count = memory_map_size / memory_map_descriptor_size;
    while (memory_map_i < memory_map_entry_count) : (memory_map_i += 1) {
        const memory_map_entry = @intToPtr(*MemoryDescriptor, @ptrToInt(memory_map) + memory_map_i * memory_map_descriptor_size);
        if (memory_map_entry.type == .LoaderData)
            logger.debug("Entry {s}. Page count: {}. Address: 0x{x}. Virtual: 0x{x}. Can execute: {}", .{ @tagName(memory_map_entry.type), memory_map_entry.number_of_pages, memory_map_entry.physical_start, memory_map_entry.virtual_start, !memory_map_entry.attribute.xp });
    }

    const file_header = @ptrCast(*const ELF.FileHeader, @alignCast(@alignOf(ELF.FileHeader), kernel_file_content.ptr));
    if (!file_header.is_valid()) @panic("Trying to load as ELF file a corrupted ELF file");

    const entry_point = file_header.entry;

    assert(file_header.program_header_size == @sizeOf(ELF.ProgramHeader));
    assert(file_header.section_header_size == @sizeOf(ELF.SectionHeader));
    // TODO: further checking
    const program_headers = @intToPtr([*]const ELF.ProgramHeader, @ptrToInt(file_header) + file_header.program_header_offset)[0..file_header.program_header_entry_count];

    var program_segments: []ProgramSegment = &.{};
    program_segments.ptr = @intToPtr([*]ProgramSegment, bootloader_information.memory.allocate(@intCast(u32, common.align_forward(@sizeOf(ProgramSegment) * program_headers.len, page_size)), MemoryCategory.kernel_segment_descriptors) catch @panic("unable to allocate memory for program segments"));
    assert(program_segments.len == 0);

    var kernel_address_space = blk: {
        logger.debug("Big chunk", .{});
        const chunk_address = bootloader_information.memory.allocate_aligned(VirtualAddressSpace.needed_physical_memory_for_bootstrapping_kernel_address_space, page_size, MemoryCategory.page_tables) catch @panic("Unable to get physical memory to bootstrap kernel address space");
        const kernel_address_space_physical_region = PhysicalMemoryRegion{
            .address = PhysicalAddress.new(chunk_address),
            .size = VirtualAddressSpace.needed_physical_memory_for_bootstrapping_kernel_address_space,
        };
        break :blk VirtualAddressSpace.initialize_kernel_address_space_bsp(kernel_address_space_physical_region);
    };

    var all_segments_size: u32 = 0;
    for (program_headers) |*ph| {
        switch (ph.type) {
            .load => {
                if (ph.size_in_memory == 0) continue;
                const address_misalignment = ph.virtual_address & (page_size - 1);

                if (address_misalignment != 0) {
                    @panic("ELF PH segment size is supposed to be page-aligned");
                }

                if (!common.is_aligned(ph.offset, page_size)) {
                    @panic("ELF PH offset is supposed to be page-aligned");
                }

                if (!ph.flags.readable) {
                    @panic("ELF program segment is marked as non-readable");
                }

                if (ph.size_in_file != ph.size_in_memory) {
                    @panic("ELF program segment file size is smaller than memory size");
                }

                const segment_index = program_segments.len;
                program_segments.len += 1;
                const segment = &program_segments[segment_index];
                segment.* = .{
                    .physical = 0, // batch allocate later
                    .virtual = ph.virtual_address,
                    .size = @intCast(u32, ph.size_in_memory),
                    .file_offset = @intCast(u32, ph.offset),
                    .mappings = .{
                        .write = ph.flags.writable,
                        .execute = ph.flags.executable,
                    },
                };

                const aligned_segment_size = @intCast(u32, common.align_forward(segment.size + address_misalignment, page_size));
                all_segments_size += aligned_segment_size;
            },
            else => {
                logger.warn("Unhandled PH {s}", .{@tagName(ph.type)});
            },
        }
    }

    const bootinfo_physical = PhysicalAddress.new(@ptrToInt(bootloader_information));
    const bootinfo_higher_half = bootinfo_physical.to_higher_half_virtual_address();
    logger.debug("Started mapping bootloader information: {}", .{bootinfo_physical});
    VAS.bootstrap_map(&kernel_address_space, bootinfo_physical, bootinfo_higher_half, common.align_forward(@sizeOf(BootloaderInformation), page_size) >> page_shifter, .{ .write = true, .execute = false }, &bootloader_information.memory.allocator, null);
    logger.debug("Ended mapping bootloader information", .{});

    logger.debug("Allocate aligned: {}", .{all_segments_size});
    const segments_allocation = bootloader_information.memory.allocate_aligned(all_segments_size, page_size, MemoryCategory.kernel_segments) catch @panic("Unable to allocate memory for kernel segments");
    var allocated_segment_memory: u32 = 0;

    for (program_segments) |*segment| {
        const virtual_address = VirtualAddress.new(segment.virtual & 0xffff_ffff_ffff_f000);
        const address_misalignment = @intCast(u32, segment.virtual - virtual_address.value);
        const aligned_segment_size = @intCast(u32, common.align_forward(segment.size + address_misalignment, page_size));
        const physical_address = PhysicalAddress.new(segments_allocation + allocated_segment_memory); // UEFI uses identity mapping
        segment.physical = physical_address.value + address_misalignment;
        allocated_segment_memory += aligned_segment_size;
        const dst_slice = @intToPtr([*]u8, segment.physical)[0..segment.size];
        const src_slice = @intToPtr([*]const u8, @ptrToInt(kernel_file_content.ptr) + segment.file_offset)[0..segment.size];
        if (!(dst_slice.len >= src_slice.len)) {
            @panic("WTFFFFFFF");
        }
        assert(dst_slice.len >= src_slice.len);
        common.copy(u8, dst_slice, src_slice);
        const segment_page_count = aligned_segment_size >> page_shifter;
        VAS.bootstrap_map(&kernel_address_space, physical_address, virtual_address, segment_page_count, .{ .write = segment.mappings.write, .execute = segment.mappings.execute }, &bootloader_information.memory.allocator, null);
    }

    assert(allocated_segment_memory == all_segments_size);

    // TODO: there can be an enourmous bug here because we dont map page tables

    const stack_size = 10 * page_size;
    const gdt_size = page_size;
    const trampoline_allocation_size = loader_file.size + stack_size + gdt_size;
    // TODO: not junk but we don't need to categoryze it now
    const physical_trampoline_allocation = PhysicalAddress.new(bootloader_information.memory.allocate_aligned(trampoline_allocation_size, page_size, MemoryCategory.junk) catch @panic("wtf"));
    const stack = physical_trampoline_allocation.offset(loader_file.size);
    const gdt = physical_trampoline_allocation.offset(loader_file.size + stack_size);

    const code_physical = PhysicalAddress.new(@ptrToInt(loader_file_content.ptr));
    VAS.bootstrap_map(&kernel_address_space, code_physical, code_physical.to_identity_mapped_virtual_address(), loader_file.size >> page_shifter, .{ .write = false, .execute = true }, &bootloader_information.memory.allocator, null);
    VAS.bootstrap_map(&kernel_address_space, stack, stack.to_higher_half_virtual_address(), stack_size >> page_shifter, .{ .write = true, .execute = false }, &bootloader_information.memory.allocator, null);
    VAS.bootstrap_map(&kernel_address_space, gdt, gdt.to_higher_half_virtual_address(), gdt_size >> page_shifter, .{ .write = true, .execute = false }, &bootloader_information.memory.allocator, null);

    // Make sure every page table is mapped
    logger.debug("Started mapping page tables...", .{});
    {
        const category = bootloader_information.memory.categories[@enumToInt(MemoryCategory.page_tables)];
        const physical = PhysicalAddress.new(bootloader_information.memory.address + category.offset);
        const virtual = physical.to_higher_half_virtual_address();
        const page_count = category.size >> page_shifter;
        VAS.bootstrap_map(&kernel_address_space, physical, virtual, page_count, .{ .write = true, .execute = false }, &bootloader_information.memory.allocator, null);
    }
    logger.debug("Ended mapping page tables...", .{});

    const load_kernel_function = code_physical.to_identity_mapped_virtual_address().access(*const LoadKernelFunction);
    const stack_top = stack.to_higher_half_virtual_address().value + stack_size;

    const gdt_descriptor_identity = gdt.to_identity_mapped_virtual_address().offset(@sizeOf(GDT.Table)).access(*GDT.Descriptor);
    gdt_descriptor_identity.* = gdt.to_identity_mapped_virtual_address().access(*GDT.Table).fill_with_offset(common.config.kernel_higher_half_address);
    logger.debug("About to jump to the kernel. Map address space: 0x{x}. GDT descriptor: ({}, {}). Logging is off", .{ @bitCast(u64, kernel_address_space.arch.cr3), gdt_descriptor_identity.limit, gdt_descriptor_identity.address });
    const gdt_descriptor_higher_half = gdt.to_higher_half_virtual_address().offset(@sizeOf(GDT.Table)).access(*GDT.Descriptor);

    load_kernel_function(bootinfo_higher_half.access(*BootloaderInformation), entry_point, kernel_address_space.arch.cr3, stack_top, gdt_descriptor_higher_half);
}

pub const log_level = common.std.log.Level.debug;

pub fn log(comptime level: common.std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
    switch (common.cpu.arch) {
        .x86_64 => {
            if (config.real_hardware) {
                var buffer: [4096]u8 = undefined;
                const formatted_buffer = common.std.fmt.bufPrint(buffer[0..], prefix ++ format ++ "\n", args) catch unreachable;

                for (formatted_buffer) |c| {
                    const fake_c = [2]u16{ c, 0 };
                    _ = UEFI.get_system_table().con_out.?.outputString(@ptrCast(*const [1:0]u16, &fake_c));
                }
            } else {
                debug_writer.print(prefix ++ format ++ "\n", args) catch unreachable;
            }
        },
        else => @compileError("Unsupported CPU architecture"),
    }
}

pub fn panic(message: []const u8, _: ?*common.std.builtin.StackTrace, _: ?usize) noreturn {
    UEFI.panic("{s}", .{message});
}

fn flush_new_line() !void {
    switch (common.cpu.arch) {
        .x86_64 => {
            if (!config.real_hardware) {
                try debug_writer.writeByte('\n');
            }
        },
        else => @compileError("arch not supported"),
    }
}

const Writer = common.Writer(void, UEFI.Error, e9_write);
const debug_writer = Writer{ .context = {} };
fn e9_write(_: void, bytes: []const u8) UEFI.Error!usize {
    const bytes_left = asm volatile (
        \\cld
        \\rep outsb
        : [ret] "={rcx}" (-> usize),
        : [dest] "{dx}" (0xe9),
          [src] "{rsi}" (bytes.ptr),
          [len] "{rcx}" (bytes.len),
    );
    return bytes.len - bytes_left;
}
