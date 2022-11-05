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
const MemoryMap = UEFI.MemoryMap;
const ProgramSegment = UEFI.ProgramSegment;
const Protocol = UEFI.Protocol;
const page_table_estimated_size = UEFI.page_table_estimated_size;
const SimpleFilesystemProtocol = UEFI.SimpleFilesystemProtocol;
const SystemTable = UEFI.SystemTable;

const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const VirtualAddress = privileged.VirtualAddress;
const VirtualAddressSpace = privileged.VirtualAddressSpace;
const VirtualMemoryRegion = privileged.VirtualMemoryRegion;

const arch = @import("arch");
const CPU = arch.CPU;
const GDT = x86_64.GDT;
const paging = arch.paging;
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

        @panic("Unable to find RSDP");
    };

    const filesystem_root = blk: {
        const loaded_image = Protocol.open(LoadedImageProtocol, boot_services, handle);
        const filesystem_protocol = Protocol.open(SimpleFilesystemProtocol, boot_services, loaded_image.device_handle orelse unreachable);
        var root: *FileProtocol = undefined;
        UEFI.result(@src(), filesystem_protocol.openVolume(&root));
        break :blk root;
    };

    var kernel_file = File.get(filesystem_root, "kernel.elf");
    logger.debug("Got files", .{});

    const bootstrap_memory = blk: {
        var memory_map_size: usize = 0;
        var memory_map_key: usize = 0;
        var memory_map_descriptor_size: usize = 0;
        var memory_map_descriptor_version: u32 = 0;
        _ = boot_services.getMemoryMap(&memory_map_size, null, &memory_map_key, &memory_map_descriptor_size, &memory_map_descriptor_version);
        logger.debug("Expected size: {}. Actual size: {}. Descriptor version: {}", .{ memory_map_descriptor_size, @sizeOf(MemoryDescriptor), memory_map_descriptor_version });
        memory_map_size = common.align_forward(memory_map_size + UEFI.page_size, UEFI.page_size);

        const size = kernel_file.size + memory_map_size;

        //allocatePages: std.meta.FnPtr(fn (alloc_type: AllocateType, mem_type: MemoryType, pages: usize, memory: *[*]align(4096) u8) callconv(.C) Status),
        var memory: [*]align(UEFI.page_size) u8 = undefined;
        UEFI.result(@src(), boot_services.allocatePages(.AllocateAnyPages, .LoaderData, size >> UEFI.page_shifter, &memory));
        break :blk memory;
    };

    const kernel_file_content = kernel_file.read(bootstrap_memory[0..kernel_file.size]);

    logger.debug("Trying to get memory map", .{});

    var memory_manager = MemoryManager{
        .map = UEFI.MemoryMap{
            .region = .{
                .address = VirtualAddress.new(@ptrToInt(bootstrap_memory) + kernel_file.size),
                .size = 0,
            },
            .descriptor_size = 0,
        },
    };

    {
        var memory_map_key: usize = 0;
        var memory_map_size: usize = 0;
        var memory_map_descriptor_size: usize = 0;
        _ = boot_services.getMemoryMap(&memory_map_size, null, &memory_map_key, &memory_map_descriptor_size, &memory_manager.map.descriptor_version);

        UEFI.result(@src(), boot_services.getMemoryMap(&memory_map_size, memory_manager.map.region.address.access([*]MemoryDescriptor), &memory_map_key, &memory_map_descriptor_size, &memory_manager.map.descriptor_version));
        memory_manager.map.region.size = @intCast(u32, memory_map_size);
        memory_manager.map.descriptor_size = @intCast(u32, memory_map_descriptor_size);
        assert(memory_map_size % memory_manager.map.descriptor_size == 0);
        logger.debug("Memory map size: {}", .{memory_map_size});

        logger.debug("Exiting boot services...", .{});
        UEFI.result(@src(), boot_services.exitBootServices(handle, memory_map_key));
    }

    memory_manager.generate_size_counters();

    const file_header = @ptrCast(*const ELF.FileHeader, @alignCast(@alignOf(ELF.FileHeader), kernel_file_content.ptr));
    if (!file_header.is_valid()) @panic("Trying to load as ELF file a corrupted ELF file");
    const entry_point = file_header.entry;

    assert(file_header.program_header_size == @sizeOf(ELF.ProgramHeader));
    assert(file_header.section_header_size == @sizeOf(ELF.SectionHeader));
    // TODO: further checking

    const program_headers = @intToPtr([*]const ELF.ProgramHeader, @ptrToInt(file_header) + file_header.program_header_offset)[0..file_header.program_header_entry_count];
    var program_segments: []ProgramSegment = &.{};
    program_segments.ptr = @intToPtr([*]ProgramSegment, memory_manager.allocate(common.align_forward(@sizeOf(ProgramSegment) * program_headers.len, UEFI.page_size) >> UEFI.page_shifter) catch @panic("unable to allocate memory for program segments"));
    assert(program_segments.len == 0);

    var all_segments_size: u32 = 0;
    for (program_headers) |*ph| {
        switch (ph.type) {
            .load => {
                if (ph.size_in_memory == 0) continue;
                const address_misalignment = ph.virtual_address & (UEFI.page_size - 1);

                if (address_misalignment != 0) {
                    @panic("ELF PH segment size is supposed to be page-aligned");
                }

                if (!common.is_aligned(ph.offset, UEFI.page_size)) {
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

                const aligned_segment_size = @intCast(u32, common.align_forward(segment.size + address_misalignment, UEFI.page_size));
                all_segments_size += aligned_segment_size;
            },
            else => {
                logger.warn("Unhandled PH {s}", .{@tagName(ph.type)});
            },
        }
    }

    var kernel_address_space = blk: {
        logger.debug("Big chunk", .{});
        const chunk_address = memory_manager.allocate(VirtualAddressSpace.needed_physical_memory_for_bootstrapping_kernel_address_space >> UEFI.page_shifter) catch @panic("Unable to get physical memory to bootstrap kernel address space");
        const kernel_address_space_physical_region = PhysicalMemoryRegion{
            .address = PhysicalAddress.new(chunk_address),
            .size = VirtualAddressSpace.needed_physical_memory_for_bootstrapping_kernel_address_space,
        };
        break :blk VirtualAddressSpace.initialize_kernel_address_space_bsp(kernel_address_space_physical_region);
    };

    logger.debug("Allocate aligned: {}", .{all_segments_size});
    const segments_allocation = memory_manager.allocate(all_segments_size >> UEFI.page_shifter) catch @panic("Unable to allocate memory for kernel segments");
    var allocated_segment_memory: u32 = 0;

    for (program_segments) |*segment| {
        const virtual_address = VirtualAddress.new(segment.virtual & 0xffff_ffff_ffff_f000);
        const address_misalignment = @intCast(u32, segment.virtual - virtual_address.value);
        const aligned_segment_size = @intCast(u32, common.align_forward(segment.size + address_misalignment, UEFI.page_size));
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
        paging.bootstrap_map(&kernel_address_space, physical_address, virtual_address, aligned_segment_size, .{ .write = segment.mappings.write, .execute = segment.mappings.execute }, &memory_manager.allocator) catch @panic("unable to map program segment");
    }

    assert(allocated_segment_memory == all_segments_size);

    const stack_top = blk: {
        const stack_page_count = 10;
        const stack_size = stack_page_count << UEFI.page_shifter;
        const stack_physical_address = PhysicalAddress.new(memory_manager.allocate(stack_page_count) catch @panic("Unable to allocate memory for stack"));
        break :blk stack_physical_address.to_higher_half_virtual_address().value + stack_size;
    };

    const gdt_descriptor = blk: {
        const gdt_page_count = 1;
        const gdt_physical_address = PhysicalAddress.new(memory_manager.allocate(gdt_page_count) catch @panic("Unable to allocate memory for GDT"));
        const gdt_descriptor_identity = gdt_physical_address.to_identity_mapped_virtual_address().offset(@sizeOf(GDT.Table)).access(*GDT.Descriptor);
        gdt_descriptor_identity.* = gdt_physical_address.to_identity_mapped_virtual_address().access(*GDT.Table).fill_with_offset(common.config.kernel_higher_half_address);
        break :blk gdt_physical_address.to_higher_half_virtual_address().offset(@sizeOf(GDT.Table)).access(*GDT.Descriptor);
    };

    {
        const trampoline_code_start = @ptrToInt(&load_kernel);
        const trampoline_code_size = @ptrToInt(&kernel_trampoline_end) - @ptrToInt(&kernel_trampoline_start);
        const code_physical_base_page = PhysicalAddress.new(common.align_backward(trampoline_code_start, UEFI.page_size));
        const misalignment = trampoline_code_start - code_physical_base_page.value;
        const trampoline_size_to_map = common.align_forward(misalignment + trampoline_code_size, UEFI.page_size);
        paging.bootstrap_map(&kernel_address_space, code_physical_base_page, code_physical_base_page.to_identity_mapped_virtual_address(), trampoline_size_to_map, .{ .write = false, .execute = true }, &memory_manager.allocator) catch @panic("Unable to map kernel trampoline code");
    }

    var bootloader_information = PhysicalAddress.new(memory_manager.allocate(common.align_forward(@sizeOf(BootloaderInformation), UEFI.page_size) >> UEFI.page_shifter) catch @panic("Unable to allocate memory for bootloader information"));

    // Map all usable memory to avoid kernel delays later
    // TODO:
    // 1. Divide memory per CPU to avoid shared memory
    // 2. User manager
    var map_iterator = memory_manager.map.iterator();
    while (map_iterator.next(memory_manager.map)) |entry| {
        if (entry.type == .ConventionalMemory) {
            const physical_address = PhysicalAddress.new(entry.physical_start);
            const virtual_address = physical_address.to_higher_half_virtual_address();
            const size = entry.number_of_pages * arch.valid_page_sizes[0];
            paging.bootstrap_map(&kernel_address_space, physical_address, virtual_address, size, .{ .write = true, .execute = false }, &memory_manager.allocator) catch @panic("Unable to map page tables");
        }
    }

    var allocated_size: usize = 0;
    for (memory_manager.size_counters.counters) |counter| {
        allocated_size += counter;
    }

    logger.debug("Allocated size: 0x{x}", .{allocated_size * arch.valid_page_sizes[0]});

    bootloader_information.to_identity_mapped_virtual_address().access(*BootloaderInformation).* = .{
        .kernel_segments = program_segments,
        .memory_map = memory_manager.map.to_higher_half(),
        .counters = memory_manager.size_counters.to_higher_half(),
        .rsdp_physical_address = rsdp_physical_address,
    };

    load_kernel(bootloader_information.to_higher_half_virtual_address().access(*BootloaderInformation), entry_point, kernel_address_space.arch.cr3, stack_top, gdt_descriptor);
}

extern const kernel_trampoline_start: *volatile u8;
extern const kernel_trampoline_end: *volatile u8;

extern fn load_kernel(bootloader_information: *BootloaderInformation, kernel_start_address: u64, cr3: arch.x86_64.registers.cr3, stack: u64, gdt_descriptor: *arch.x86_64.GDT.Descriptor) callconv(.SysV) noreturn;
comptime {
    asm (
        \\.intel_syntax noprefix
        \\.global load_kernel
        \\.global kernel_trampoline_start
        \\.global kernel_trampoline_end
        \\kernel_trampoline_start:
        \\load_kernel:
        \\mov cr3, rdx
        \\lgdt [r8]
        \\mov rsp, rcx
        \\mov rax, 0x10
        \\mov ds, rax
        \\mov es, rax
        \\mov fs, rax
        \\mov gs, rax
        \\mov ss, rax
        \\call set_cs
        \\xor rbp, rbp
        \\jmp rsi
        \\set_cs:
        \\pop rax
        \\push 0x08
        \\push rax
        \\retfq
        \\kernel_trampoline_end:
    );

    assert(@offsetOf(GDT.Table, "code_64") == 0x08);
    assert(@offsetOf(GDT.Table, "data_64") == 0x10);
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

const MemoryManager = struct {
    map: MemoryMap,
    size_counters: MemoryMap.SizeCounters = .{},
    allocator: CustomAllocator = .{
        .callback_allocate = physical_allocate,
        .callback_resize = physical_resize,
        .callback_free = physical_free,
    },

    fn allocate(memory_manager: *MemoryManager, number_of_4k_pages: usize) !usize {
        var it = memory_manager.map.iterator();
        var index: usize = 0;
        while (it.next(memory_manager.map)) |entry| {
            if (entry.type == .ConventionalMemory) {
                defer index += 1;

                const number_of_page_offset = memory_manager.size_counters.counters[index];
                if (entry.number_of_pages - number_of_page_offset >= number_of_4k_pages) {
                    const address = entry.physical_start + (number_of_page_offset << UEFI.page_shifter);
                    memory_manager.size_counters.counters[index] += @intCast(u32, number_of_4k_pages);
                    return address;
                }
            }
        }

        return PhysicalError.oom;
    }

    pub fn generate_size_counters(memory_manager: *MemoryManager) void {
        var memory_map_iterator = memory_manager.map.iterator();
        var conventional_entry_count: u32 = 0;

        while (memory_map_iterator.next(memory_manager.map)) |entry| {
            conventional_entry_count += @boolToInt(entry.type == .ConventionalMemory);
        }

        const size_to_allocate_memory_map_size_counters = conventional_entry_count * @sizeOf(u32);

        var conventional_memory_index: u32 = 0;
        memory_map_iterator.reset();

        while (memory_map_iterator.next(memory_manager.map)) |entry| {
            if (entry.type == .ConventionalMemory) {
                defer conventional_memory_index += 1;
                if (entry.number_of_pages << UEFI.page_shifter > size_to_allocate_memory_map_size_counters) {
                    const index = conventional_memory_index;
                    const counters = @intToPtr([*]u32, entry.physical_start)[0..conventional_entry_count];
                    common.std.mem.set(u32, counters, 0);
                    counters[index] = size_to_allocate_memory_map_size_counters;

                    memory_manager.size_counters = .{
                        .counters = counters,
                    };

                    const size_for_copy = common.align_forward(memory_manager.map.region.size, UEFI.page_size);
                    const memory_map_copy_allocation = PhysicalMemoryRegion{
                        .address = PhysicalAddress.new(memory_manager.allocate(size_for_copy >> UEFI.page_shifter) catch @panic("failed to allocate memory map copy")),
                        .size = memory_manager.map.region.size,
                    };

                    const memory_copy = memory_map_copy_allocation.to_identity_mapped_virtual_address().access_bytes();
                    const memory_original = memory_manager.map.region.access_bytes();
                    common.copy(u8, memory_copy, memory_original);
                    memory_manager.map.region = memory_map_copy_allocation.to_identity_mapped_virtual_address();
                    return;
                }
            }
        }

        @panic("Unable to allocate memory counters");
    }
};

// This is only meant to allocate page tables
fn physical_allocate(allocator: *CustomAllocator, size: u64, alignment: u64) CustomAllocator.Error!CustomAllocator.Result {
    const memory_manager = @fieldParentPtr(MemoryManager, "allocator", allocator);
    if (alignment != arch.valid_page_sizes[0]) {
        @panic("wrong alignment");
    }
    if (!common.is_aligned(size, arch.valid_page_sizes[0])) {
        @panic("wrong alignment");
    }
    // todo: better define types
    const allocation = memory_manager.allocate(size >> UEFI.page_shifter) catch return CustomAllocator.Error.OutOfMemory;
    return CustomAllocator.Result{
        .address = allocation,
        .size = size,
    };
}

fn physical_resize(allocator: *CustomAllocator, old_memory: []u8, old_alignment: u29, new_size: usize) ?usize {
    _ = allocator;
    _ = old_memory;
    _ = old_alignment;
    _ = new_size;
    @panic("todo physical_resize");
}

fn physical_free(allocator: *CustomAllocator, memory: []u8, alignment: u29) void {
    _ = allocator;
    _ = memory;
    _ = alignment;
    @panic("todo physical_free");
}

const PhysicalError = error{
    oom,
};
