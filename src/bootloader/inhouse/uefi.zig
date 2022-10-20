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
        break :blk common.align_forward(file_info.file_size + page_size, page_size);
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
        const total_size = kernel_file_size + (kernel_file_size / 2) + memory_map_size + VirtualAddressSpace.needed_physical_memory_for_bootstrapping_kernel_address_space + (page_size << 5);
        assert(common.is_aligned(total_size, page_size));
        const total_page_count = total_size >> page_shifter;
        logger.debug("Allocating {} pages to bootstrap the kernel", .{total_page_count});
        result(@src(), boot_services.allocatePages(.AllocateAnyPages, .LoaderData, total_page_count, &pointer));
        break :blk ExtendedMemory{
            .address = @ptrToInt(pointer),
            .size = total_size,
        };
    };

    var kernel_buffer = @intToPtr([*]align(page_size) u8, extended_memory.allocate_aligned(kernel_file_size, page_size) catch @panic("oom"))[0..kernel_file_size];
    result(@src(), kernel_file.read(&kernel_buffer.len, kernel_buffer.ptr));
    logger.debug("Kernel file ({} bytes aligned to page size) read", .{kernel_file_size});

    logger.debug("Trying to get memory map", .{});
    var memory_map = @intToPtr([*]uefi.tables.MemoryDescriptor, extended_memory.allocate_aligned(memory_map_size, page_size) catch @panic("can't allocate memory for memory map"));
    var memory_map_key: usize = 0;
    var memory_map_descriptor_size: usize = 0;
    var memory_map_descriptor_version: u32 = 0;
    result(@src(), boot_services.getMemoryMap(&memory_map_size, memory_map, &memory_map_key, &memory_map_descriptor_size, &memory_map_descriptor_version));
    assert(memory_map_size % memory_map_descriptor_size == 0);
    logger.debug("Memory map size: {}", .{memory_map_size});

    var memory_map_i: u64 = 0;
    const memory_map_entry_count = memory_map_size / memory_map_descriptor_size;
    while (memory_map_i < memory_map_entry_count) : (memory_map_i += 1) {
        const memory_map_entry = @intToPtr(*uefi.tables.MemoryDescriptor, @ptrToInt(memory_map) + memory_map_i * memory_map_descriptor_size);
        if (memory_map_entry.type == .LoaderData)
            logger.debug("Entry {s}. Page count: {}. Address: 0x{x}. Virtual: 0x{x}", .{ @tagName(memory_map_entry.type), memory_map_entry.number_of_pages, memory_map_entry.physical_start, memory_map_entry.virtual_start });
    }

    const file_header = @ptrCast(*const ELF.FileHeader, @alignCast(@alignOf(ELF.FileHeader), kernel_buffer.ptr));
    if (!file_header.is_valid()) @panic("Trying to load as ELF file a corrupted ELF file");

    assert(file_header.program_header_size == @sizeOf(ELF.ProgramHeader));
    assert(file_header.section_header_size == @sizeOf(ELF.SectionHeader));
    // TODO: further checking
    const program_headers = @intToPtr([*]const ELF.ProgramHeader, @ptrToInt(file_header) + file_header.program_header_offset)[0..file_header.program_header_entry_count];

    var program_segments: []ProgramSegment = &.{};
    program_segments.ptr = @intToPtr([*]ProgramSegment, extended_memory.allocate(@sizeOf(ProgramSegment) * program_headers.len) catch @panic("unable to allocate memory for program segments"));
    assert(program_segments.len == 0);

    var kernel_address_space = blk: {
        const chunk_address = extended_memory.allocate_aligned(VirtualAddressSpace.needed_physical_memory_for_bootstrapping_kernel_address_space, page_size) catch @panic("Unable to get physical memory to bootstrap kernel address space");
        const kernel_address_space_physical_region = PhysicalMemoryRegion{
            .address = PhysicalAddress.new(chunk_address),
            .size = VirtualAddressSpace.needed_physical_memory_for_bootstrapping_kernel_address_space,
        };
        break :blk VirtualAddressSpace.initialize_kernel_address_space_bsp(kernel_address_space_physical_region);
    };

    for (program_headers) |*ph| {
        switch (ph.type) {
            .load => {
                if (ph.size_in_memory == 0) continue;
                const misalignment = ph.virtual_address & (page_size - 1);
                const segment_size = common.align_forward(ph.size_in_memory + misalignment, page_size);

                if (misalignment != 0) {
                    @panic("ELF PH segment size is supposed to be page-aligned");
                }

                if (!common.is_aligned(ph.offset, page_size)) {
                    @panic("ELF PH offset is supposed to be page-aligned");
                }

                if (!ph.flags.readable) {
                    @panic("ELF program segment is marked as non-readable");
                }

                if (ph.size_in_file < ph.size_in_memory) {
                    @panic("ELF program segment file size is smaller than memory size");
                }

                const kernel_segment_virtual_address = extended_memory.allocate_aligned(segment_size, page_size) catch @panic("Unable to allocate memory for ELF segment");
                const segment_start = kernel_segment_virtual_address + misalignment;
                const dst_slice = @intToPtr([*]u8, segment_start)[0..ph.size_in_memory];
                const src_slice = @intToPtr([*]const u8, @ptrToInt(kernel_buffer.ptr) + ph.offset)[0..ph.size_in_file];
                assert(dst_slice.len >= src_slice.len);
                common.copy(u8, dst_slice, src_slice);

                const segment_index = program_segments.len;
                program_segments.len += 1;
                const segment = &program_segments[segment_index];
                segment.* = .{
                    .physical = segment_start, // UEFI uses identity mapping
                    .virtual = ph.virtual_address,
                    .size = ph.size_in_memory,
                    .mappings = .{
                        .write = ph.flags.writable,
                        .execute = ph.flags.executable,
                    },
                };

                const physical_address = PhysicalAddress.new(kernel_segment_virtual_address);
                const virtual_address = VirtualAddress.new(ph.virtual_address & 0xffff_ffff_ffff_f000);
                const segment_page_count = segment_size >> page_shifter;
                VAS.bootstrap_map(&kernel_address_space, physical_address, virtual_address, segment_page_count, .{ .write = segment.mappings.write, .execute = segment.mappings.execute }, &extended_memory.allocator, null);
            },
            else => {
                logger.warn("Unhandled PH {s}", .{@tagName(ph.type)});
            },
        }
    }

    success();
}

fn physical_allocate(allocator: *CustomAllocator, size: u64, alignment: u64) CustomAllocator.Error!CustomAllocator.Result {
    const extended_memory = @fieldParentPtr(ExtendedMemory, "allocator", allocator);
    // todo: better define types
    const allocation = extended_memory.allocate_aligned(size, @intCast(u29, alignment)) catch unreachable;
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

const ExtendedMemory = struct {
    address: u64,
    size: u64,
    allocated: u64 = 0,
    allocator: CustomAllocator = .{
        .callback_allocate = physical_allocate,
        .callback_resize = physical_resize,
        .callback_free = physical_free,
    },

    pub fn allocate(extended_memory: *ExtendedMemory, bytes: usize) EFIError!u64 {
        return extended_memory.allocate_aligned(bytes, 1);
    }

    pub fn allocate_aligned(extended_memory: *ExtendedMemory, bytes: usize, alignment: u29) EFIError!u64 {
        const allocated_aligned = common.align_forward(extended_memory.allocated, alignment);
        if (bytes >= extended_memory.size - allocated_aligned) {
            return EFIError.BufferTooSmall;
        }

        extended_memory.allocated = allocated_aligned + bytes;
        return extended_memory.address + allocated_aligned;
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
    size: u64,
    mappings: extern struct {
        write: bool,
        execute: bool,
    },
};
