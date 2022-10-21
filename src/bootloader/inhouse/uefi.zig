const common = @import("common");
const assert = common.assert;
const config = common.config;
const CustomAllocator = common.CustomAllocator;
const ELF = common.ELF;
const logger = common.log.scoped(.UEFI);
const uefi = common.std.os.uefi;
const uefi_error = uefi.Status.err;
const BlockIOProtocol = uefi.protocols.BlockIoProtocol;
const BootServices = uefi.tables.BootServices;
const FileInfo = uefi.protocols.FileInfo;
const FileProtocol = uefi.protocols.FileProtocol;
const GraphicsOutputProtocol = uefi.protocols.GraphicsOutputProtocol;
const LoadedImageProtocol = uefi.protocols.LoadedImageProtocol;
const SimpleTextOutputProtocol = uefi.protocols.SimpleTextOutputProtocol;
const SimpleFilesystemProtocol = uefi.protocols.SimpleFileSystemProtocol;
const Status = uefi.Status;
const SystemTable = uefi.tables.SystemTable;
const EFIError = Status.EfiError;

const str16 = common.std.unicode.utf8ToUtf16LeStringLiteral;

const privileged = @import("privileged");
const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const VirtualAddress = privileged.VirtualAddress;
const VirtualAddressSpace = privileged.VirtualAddressSpace;

const arch = @import("arch");
const page_size = arch.page_size;
const page_shifter = arch.page_shifter;
const VAS = arch.VAS;
const x86_64 = arch.x86_64;
const GDT = x86_64.GDT;

const page_table_estimated_size = VirtualAddressSpace.needed_physical_memory_for_bootstrapping_kernel_address_space + 200 * page_size;

pub fn main() noreturn {
    const system_table = uefi.system_table;
    const boot_services = system_table.boot_services orelse @panic("boot services");
    const out = system_table.con_out orelse @panic("con out");
    result(@src(), out.reset(true));
    result(@src(), out.clearScreen());
    flush_new_line() catch unreachable;

    const revision_string = switch (system_table.firmware_revision) {
        uefi.tables.SystemTable.revision_1_02 => "1.02",
        uefi.tables.SystemTable.revision_1_10 => "1.10",
        uefi.tables.SystemTable.revision_2_00 => "2.00",
        uefi.tables.SystemTable.revision_2_10 => "2.10",
        uefi.tables.SystemTable.revision_2_20 => "2.20",
        uefi.tables.SystemTable.revision_2_30 => "2.30",
        uefi.tables.SystemTable.revision_2_31 => "2.31",
        uefi.tables.SystemTable.revision_2_40 => "2.40",
        uefi.tables.SystemTable.revision_2_50 => "2.50",
        uefi.tables.SystemTable.revision_2_60 => "2.60",
        uefi.tables.SystemTable.revision_2_70 => "2.70",
        uefi.tables.SystemTable.revision_2_80 => "2.80",
        else => "Unrecognized EFI version: check that Zig UEFI standard library is up-to-date and, if not, BIOS is corrupted",
    };

    logger.debug("EFI revision: {s}", .{revision_string});

    const configuration_tables = system_table.configuration_table[0..system_table.number_of_table_entries];
    const rsdp_address = blk: {
        for (configuration_tables) |configuration_table| {
            if (configuration_table.vendor_guid.eql(uefi.tables.ConfigurationTable.acpi_20_table_guid)) {
                break :blk @ptrToInt(configuration_table.vendor_table);
            }
        }

        uefi_panic("Unable to find RSDP", .{});
    };

    logger.debug("RSDP: 0x{x}", .{rsdp_address});
    const loaded_image = Protocol.open(LoadedImageProtocol, boot_services, uefi.handle);
    const filesystem_protocol = Protocol.open(SimpleFilesystemProtocol, boot_services, loaded_image.device_handle orelse unreachable);
    var filesystem_root: *FileProtocol = undefined;
    result(@src(), filesystem_protocol.openVolume(&filesystem_root));
    var kernel_file: *FileProtocol = undefined;
    const kernel_filename = str16("kernel.elf");
    result(@src(), filesystem_root.open(&kernel_file, kernel_filename, FileProtocol.efi_file_mode_read, 0));
    const kernel_file_size = blk: {
        // TODO: figure out why it is succeeding with 16 and not with 8
        var buffer: [@sizeOf(FileInfo) + @sizeOf(@TypeOf(kernel_filename)) + 16]u8 align(@alignOf(FileInfo)) = undefined;
        var file_info_size = buffer.len;
        result(@src(), kernel_file.getInfo(&uefi.protocols.FileInfo.guid, &file_info_size, &buffer));
        const file_info = @ptrCast(*FileInfo, &buffer);
        logger.debug("Unaligned kernel file size: {}", .{file_info.file_size});
        break :blk @intCast(u32, common.align_forward(file_info.file_size + page_size, page_size));
    };

    var memory_map_size = blk: {
        var memory_map_size: usize = 0;
        var memory_map_key: usize = 0;
        var memory_map_descriptor_size: usize = 0;
        var memory_map_descriptor_version: u32 = 0;
        _ = boot_services.getMemoryMap(&memory_map_size, null, &memory_map_key, &memory_map_descriptor_size, &memory_map_descriptor_version);
        break :blk common.align_forward(memory_map_size + page_size, page_size);
    };

    var extended_memory = blk: {
        // TODO: don't hardcode the last part

        var pointer: [*]align(page_size) u8 = undefined;
        const total_size = @intCast(u32, kernel_file_size + (kernel_file_size / 2) + memory_map_size + page_table_estimated_size + (page_size << 5));
        assert(common.is_aligned(total_size, page_size));
        const total_page_count = total_size >> page_shifter;
        logger.debug("Allocating {} pages to bootstrap the kernel", .{total_page_count});
        result(@src(), boot_services.allocatePages(.AllocateAnyPages, .LoaderData, total_page_count, &pointer));
        break :blk ExtendedMemory{
            .address = @ptrToInt(pointer),
            .size = total_size,
        };
    };

    var kernel_buffer = @intToPtr([*]align(page_size) u8, extended_memory.allocate_aligned(kernel_file_size, page_size, MemoryCategory.kernel_file) catch @panic("oom"))[0..kernel_file_size];
    result(@src(), kernel_file.read(&kernel_buffer.len, kernel_buffer.ptr));
    logger.debug("Kernel file ({} bytes aligned to page size) read", .{kernel_file_size});

    logger.debug("Trying to get memory map", .{});
    var memory_map = @intToPtr([*]uefi.tables.MemoryDescriptor, extended_memory.allocate_aligned(@intCast(u32, memory_map_size), page_size, MemoryCategory.memory_map) catch @panic("can't allocate memory for memory map"));
    var memory_map_key: usize = 0;
    var memory_map_descriptor_size: usize = 0;
    var memory_map_descriptor_version: u32 = 0;
    result(@src(), boot_services.getMemoryMap(&memory_map_size, memory_map, &memory_map_key, &memory_map_descriptor_size, &memory_map_descriptor_version));
    assert(memory_map_size % memory_map_descriptor_size == 0);
    logger.debug("Memory map size: {}", .{memory_map_size});

    logger.debug("Exiting boot services...", .{});
    result(@src(), boot_services.exitBootServices(uefi.handle, memory_map_key));

    var memory_map_i: u64 = 0;
    const memory_map_entry_count = memory_map_size / memory_map_descriptor_size;
    while (memory_map_i < memory_map_entry_count) : (memory_map_i += 1) {
        const memory_map_entry = @intToPtr(*uefi.tables.MemoryDescriptor, @ptrToInt(memory_map) + memory_map_i * memory_map_descriptor_size);
        if (memory_map_entry.type == .LoaderData)
            logger.debug("Entry {s}. Page count: {}. Address: 0x{x}. Virtual: 0x{x}. Can execute: {}", .{ @tagName(memory_map_entry.type), memory_map_entry.number_of_pages, memory_map_entry.physical_start, memory_map_entry.virtual_start, !memory_map_entry.attribute.xp });
    }

    const file_header = @ptrCast(*const ELF.FileHeader, @alignCast(@alignOf(ELF.FileHeader), kernel_buffer.ptr));
    if (!file_header.is_valid()) @panic("Trying to load as ELF file a corrupted ELF file");

    const entry_point = file_header.entry;

    assert(file_header.program_header_size == @sizeOf(ELF.ProgramHeader));
    assert(file_header.section_header_size == @sizeOf(ELF.SectionHeader));
    // TODO: further checking
    const program_headers = @intToPtr([*]const ELF.ProgramHeader, @ptrToInt(file_header) + file_header.program_header_offset)[0..file_header.program_header_entry_count];

    var program_segments: []ProgramSegment = &.{};
    program_segments.ptr = @intToPtr([*]ProgramSegment, extended_memory.allocate(@intCast(u32, @sizeOf(ProgramSegment) * program_headers.len), MemoryCategory.junk) catch @panic("unable to allocate memory for program segments"));
    assert(program_segments.len == 0);

    var kernel_address_space = blk: {
        logger.debug("Big chunk", .{});
        const chunk_address = extended_memory.allocate_aligned(VirtualAddressSpace.needed_physical_memory_for_bootstrapping_kernel_address_space, page_size, MemoryCategory.page_tables) catch @panic("Unable to get physical memory to bootstrap kernel address space");
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
                    .physical = 0, // UEFI uses identity mapping
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

    logger.debug("Allocate aligned: {}", .{all_segments_size});
    const segments_allocation = extended_memory.allocate_aligned(all_segments_size, page_size, MemoryCategory.kernel_segments) catch @panic("Unable to allocate memory for kernel segments");
    var allocated_segment_memory: u32 = 0;

    for (program_segments) |*segment| {
        const virtual_address = VirtualAddress.new(segment.virtual & 0xffff_ffff_ffff_f000);
        const address_misalignment = @intCast(u32, segment.virtual - virtual_address.value);
        const aligned_segment_size = @intCast(u32, common.align_forward(segment.size + address_misalignment, page_size));
        const physical_address = PhysicalAddress.new(segments_allocation + allocated_segment_memory);
        segment.physical = physical_address.value + address_misalignment;
        allocated_segment_memory += aligned_segment_size;
        const dst_slice = @intToPtr([*]u8, segment.physical)[0..segment.size];
        const src_slice = @intToPtr([*]const u8, @ptrToInt(kernel_buffer.ptr) + segment.file_offset)[0..segment.size];
        if (!(dst_slice.len >= src_slice.len)) {
            @panic("WTFFFFFFF");
        }
        assert(dst_slice.len >= src_slice.len);
        common.copy(u8, dst_slice, src_slice);
        const segment_page_count = aligned_segment_size >> page_shifter;
        VAS.bootstrap_map(&kernel_address_space, physical_address, virtual_address, segment_page_count, .{ .write = segment.mappings.write, .execute = segment.mappings.execute }, &extended_memory.allocator, null);
    }

    logger.debug("It: {}. All: {}", .{ allocated_segment_memory, all_segments_size });
    assert(allocated_segment_memory == all_segments_size);

    // TODO: there can be an enourmous bug here because we dont map page tables

    const code_size = page_size;
    const stack_size = page_size;
    const gdt_size = page_size;
    const trampoline_allocation_size = code_size + stack_size + gdt_size;
    // TODO: not junk but we don't need to categoryze it now
    const physical_trampoline_allocation = PhysicalAddress.new(extended_memory.allocate_aligned(trampoline_allocation_size, page_size, MemoryCategory.junk) catch @panic("wtf"));
    const code = physical_trampoline_allocation.offset(0);
    const stack = physical_trampoline_allocation.offset(code_size);
    const gdt = physical_trampoline_allocation.offset(code_size + stack_size);

    VAS.bootstrap_map(&kernel_address_space, code, code.to_identity_mapped_virtual_address(), code_size >> page_shifter, .{ .write = false, .execute = true }, &extended_memory.allocator, null);
    VAS.bootstrap_map(&kernel_address_space, stack, stack.to_higher_half_virtual_address(), stack_size >> page_shifter, .{ .write = true, .execute = false }, &extended_memory.allocator, null);
    VAS.bootstrap_map(&kernel_address_space, gdt, gdt.to_higher_half_virtual_address(), gdt_size >> page_shifter, .{ .write = true, .execute = false }, &extended_memory.allocator, null);

    // Make sure every page table is mapped
    logger.debug("Started mapping page tables...", .{});
    {
        const category = extended_memory.categories[@enumToInt(MemoryCategory.page_tables)];
        const physical = PhysicalAddress.new(extended_memory.address + category.offset);
        const virtual = physical.to_higher_half_virtual_address();
        const page_count = category.size >> page_shifter;
        VAS.bootstrap_map(&kernel_address_space, physical, virtual, page_count, .{ .write = true, .execute = false }, &extended_memory.allocator, null);
    }
    logger.debug("Ended mapping page tables...", .{});

    const load_kernel_address = @ptrToInt(&load_kernel_stub);
    const gdt_stub_address = @ptrToInt(&gdt_stub);
    const load_kernel_size = gdt_stub_address - load_kernel_address;
    logger.debug("Load kernel: 0x{x}. GDT stub: 0x{x}", .{ load_kernel_address, gdt_stub_address });

    const load_kernel_destination = code.to_identity_mapped_virtual_address().access([*]u8)[0..load_kernel_size];
    const load_kernel_source = @intToPtr([*]u8, load_kernel_address)[0..load_kernel_size];

    common.copy(u8, load_kernel_destination, load_kernel_source);

    logger.debug("Load kernel copied!", .{});

    const gdt_stub_offset = load_kernel_size;
    const gdt_stub_end_destination = code_size;
    const gdt_stub_end_source = code_size - load_kernel_size;

    const gdt_stub_destination = code.to_identity_mapped_virtual_address().access([*]u8)[gdt_stub_offset..gdt_stub_end_destination];
    const gdt_stub_source = @intToPtr([*]const u8, @ptrToInt(&gdt_load))[0..gdt_stub_end_source];

    common.copy(u8, gdt_stub_destination, gdt_stub_source);
    logger.debug("GDT stub copied!", .{});

    const load_kernel_function = code.to_identity_mapped_virtual_address().access(*const LoadKernelFunction);
    const gdt_load_function = code.to_identity_mapped_virtual_address().offset(gdt_stub_offset).access(*const @TypeOf(gdt_load));
    const stack_top = stack.to_higher_half_virtual_address().value + stack_size;
    logger.debug("About to jump to the kernel. Map address space: 0x{x}. Logging is off", .{@bitCast(u64, kernel_address_space.arch.cr3)});

    load_kernel_function(&extended_memory, entry_point, kernel_address_space.arch.cr3, stack_top, gdt.to_higher_half_virtual_address().access(*GDT.Table), gdt_load_function);
}

const LoadKernelFunction = fn (extended_memory: *ExtendedMemory, kernel_start_address: u64, cr3: arch.x86_64.registers.cr3, stack: u64, gdt: *GDT.Table, gdt_loader: *const @TypeOf(gdt_load)) callconv(.SysV) noreturn;

extern fn load_kernel_stub(extended_memory: *ExtendedMemory, kernel_start_address: u64, cr3: arch.x86_64.registers.cr3, stack: u64, gdt: *GDT.Table, gdt_loader: *const @TypeOf(gdt_load)) callconv(.SysV) noreturn;

comptime {
    asm (
        \\.section .text
        \\.global load_kernel_stub
        \\.align 16
        \\load_kernel_stub:
        \\mov %rdx, %cr3
        \\mov %rcx, %rsp
        \\push %rdi
        \\mov %r8, %rdi
        \\call *(%r9)
        \\cli
        \\hlt
        \\pop %rdi
        \\call *(%rsi)
        \\.align 16
        \\.global gdt_stub
        \\gdt_stub:
    );
}

extern var gdt_stub: *u8;

export fn gdt_load(gdt_address: u64) callconv(.SysV) void {
    @setRuntimeSafety(false);
    @intToPtr(*GDT.Table, gdt_address).setup();
}

// This is only meant to allocate page tables
fn physical_allocate(allocator: *CustomAllocator, size: u64, alignment: u64) CustomAllocator.Error!CustomAllocator.Result {
    const extended_memory = @fieldParentPtr(ExtendedMemory, "allocator", allocator);
    // todo: better define types
    const allocation = extended_memory.allocate_aligned(@intCast(u32, size), @intCast(u29, alignment), MemoryCategory.page_tables) catch unreachable;
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
    unreachable;
}

fn physical_free(allocator: *CustomAllocator, memory: []u8, alignment: u29) void {
    _ = allocator;
    _ = memory;
    _ = alignment;
    unreachable;
}

const MemoryCategory = enum {
    page_tables,
    kernel_file,
    kernel_segments,
    memory_map,
    junk,

    const count = common.enum_count(@This());
};

const CategoryBookingKeeping = struct {
    offset: u32 = 0,
    allocated: u32 = 0,
    size: u32 = 0,
};

const ExtendedMemory = struct {
    address: u64,
    size: u32,
    allocated: u32 = 0,
    allocator: CustomAllocator = .{
        .callback_allocate = physical_allocate,
        .callback_resize = physical_resize,
        .callback_free = physical_free,
    },
    categories: [MemoryCategory.count]CategoryBookingKeeping = [1]CategoryBookingKeeping{.{}} ** MemoryCategory.count,

    pub fn allocate(extended_memory: *ExtendedMemory, bytes: u32, category: MemoryCategory) EFIError!u64 {
        return extended_memory.allocate_aligned(bytes, 1, category);
    }

    pub fn allocate_aligned(extended_memory: *ExtendedMemory, bytes: u32, alignment: u29, category_type: MemoryCategory) EFIError!u64 {
        const category = &extended_memory.categories[@enumToInt(category_type)];

        const category_size = switch (category_type) {
            .junk => 20 * page_size,
            .page_tables => page_table_estimated_size,
            else => bytes,
        };

        switch (category_type) {
            .kernel_file,
            .kernel_segments,
            .memory_map,
            => {
                if (category.allocated != 0) @panic("static big chunks cannot be redistributed");

                logger.debug("Bytes: {}. Alignment: {}", .{ bytes, alignment });
                if (bytes % alignment != 0) @panic("WTFFFFFFFFFFFFFFFFFFFFFFFFFFF");
                assert(bytes % alignment == 0);
                const base = extended_memory.allocated;
                defer extended_memory.allocated += bytes;
                category.* = .{
                    .offset = base,
                    .allocated = bytes,
                    .size = bytes,
                };

                return extended_memory.address + extended_memory.allocated;
            },
            .junk, .page_tables => {
                if (category.allocated == 0) {
                    const base = extended_memory.allocated;
                    if (base + category_size > extended_memory.size) @panic("Category size too big");
                    defer extended_memory.allocated += category_size;

                    category.* = .{
                        .offset = base,
                        .allocated = 0,
                        .size = category_size,
                    };
                }
            },
        }

        const aligned_allocated = @intCast(u32, common.align_forward(category.allocated, alignment));
        const target_allocated = aligned_allocated + bytes;
        if (target_allocated > category_size) {
            @panic("Category size overflow");
        }

        category.allocated = target_allocated;
        const result_address = extended_memory.address + category.offset + aligned_allocated;
        return result_address;
    }
};

const Protocol = struct {
    fn locate(comptime ProtocolT: type, boot_services: *BootServices) EFIError!*ProtocolT {
        var pointer_buffer: ?*anyopaque = null;
        result(@src(), boot_services.locateProtocol(&ProtocolT.guid, null, &pointer_buffer));
        return cast(ProtocolT, pointer_buffer);
    }

    fn handle(comptime ProtocolT: type, boot_services: *BootServices, efi_handle: uefi.Handle) EFIError!*ProtocolT {
        var interface_buffer: ?*anyopaque = null;
        result(@src(), boot_services.handleProtocol(efi_handle, &ProtocolT.guid, &interface_buffer));
        return cast(ProtocolT, interface_buffer);
    }

    fn open(comptime ProtocolT: type, boot_services: *BootServices, efi_handle: uefi.Handle) *ProtocolT {
        var interface_buffer: ?*anyopaque = null;
        result(@src(), boot_services.openProtocol(efi_handle, &ProtocolT.guid, &interface_buffer, efi_handle, null, .{ .get_protocol = true }));
        return cast(ProtocolT, interface_buffer);
    }

    fn cast(comptime ProtocolT: type, ptr: ?*anyopaque) *ProtocolT {
        return @ptrCast(*ProtocolT, @alignCast(@alignOf(ProtocolT), ptr));
    }
};

fn success() noreturn {
    logger.debug("Reached to the end of the current implementation successfully!", .{});
    halt();
}

inline fn halt() noreturn {
    asm volatile (
        \\cli
        \\hlt
    );
    unreachable;
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
                    _ = uefi.system_table.con_out.?.outputString(@ptrCast(*const [1:0]u16, &fake_c));
                }
            } else {
                debug_writer.print(prefix ++ format ++ "\n", args) catch unreachable;
            }
        },
        else => @compileError("Unsupported CPU architecture"),
    }
}

pub fn panic(message: []const u8, _: ?*common.std.builtin.StackTrace, _: ?usize) noreturn {
    uefi_panic("{s}", .{message});
}

pub fn uefi_panic(comptime format: []const u8, arguments: anytype) noreturn {
    common.std.log.scoped(.PANIC).err(format, arguments);
    halt();
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

const Error = error{
    missing_con_out,
    missing_boot_services,
};

const Writer = common.Writer(void, EFIError, e9_write);
const debug_writer = Writer{ .context = {} };
fn e9_write(_: void, bytes: []const u8) EFIError!usize {
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

fn result(src: common.SourceLocation, status: Status) void {
    uefi_error(status) catch |err| {
        uefi_panic("UEFI error {} at {s}:{}:{} in function {s}", .{ err, src.file, src.line, src.column, src.fn_name });
    };
}

pub const ProgramSegment = extern struct {
    physical: u64,
    virtual: u64,
    size: u32,
    file_offset: u32,
    mappings: extern struct {
        write: bool,
        execute: bool,
    },
};
