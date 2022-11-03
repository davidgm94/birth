const common = @import("common");
const assert = common.assert;
const CustomAllocator = common.CustomAllocator;
const log = common.log.scoped(.UEFI);
const uefi = common.std.os.uefi;

pub const BootServices = uefi.tables.BootServices;
pub const ConfigurationTable = uefi.tables.ConfigurationTable;
pub const Error = Status.EfiError;
pub const FileInfo = uefi.protocols.FileInfo;
pub const FileProtocol = uefi.protocols.FileProtocol;
pub const LoadedImageProtocol = uefi.protocols.LoadedImageProtocol;
pub const Handle = uefi.Handle;
pub const MemoryDescriptor = uefi.tables.MemoryDescriptor;
pub const SimpleFilesystemProtocol = uefi.protocols.SimpleFileSystemProtocol;
pub const Status = uefi.Status;
pub const SystemTable = uefi.tables.SystemTable;
pub const uefi_error = Status.err;

const str16 = common.std.unicode.utf8ToUtf16LeStringLiteral;

const arch = @import("arch");
const CPU = arch.CPU;
const page_size = arch.page_size;
const page_shifter = arch.page_shifter;

const privileged = @import("privileged");
const PhysicalAddress = privileged.PhysicalAddress;
const VirtualAddress = privileged.VirtualAddress;
const VirtualAddressSpace = privileged.VirtualAddressSpace;
const VirtualMemoryRegion = privileged.VirtualMemoryRegion;

pub const MemoryMap = struct {
    region: VirtualMemoryRegion,
    descriptor_size: u32 = @sizeOf(MemoryDescriptor),
    descriptor_version: u32 = 1,
};

pub const BootloaderInformation = struct {
    memory: ExtendedMemory,
    kernel_segments: []ProgramSegment = &.{},
    memory_map: MemoryMap = .{
        .region = VirtualMemoryRegion{
            .address = VirtualAddress.invalid(),
            .size = 0,
        },
    },
    rsdp_physical_address: PhysicalAddress,

    pub fn new(boot_services: *BootServices, rsdp_physical_address: PhysicalAddress, kernel_file_size: usize, memory_map_size: usize, extra: usize) *BootloaderInformation {
        // TODO: don't hardcode the last part

        var pointer: [*]align(page_size) u8 = undefined;
        const total_size = @intCast(u32, common.align_forward(kernel_file_size + (kernel_file_size / 2) + memory_map_size + page_table_estimated_size + @sizeOf(BootloaderInformation) + extra, page_size));
        assert(common.is_aligned(total_size, page_size));
        const total_page_count = total_size >> page_shifter;
        result(@src(), boot_services.allocatePages(.AllocateAnyPages, .LoaderData, total_page_count, &pointer));
        var extended_memory = ExtendedMemory{
            .address = @ptrToInt(pointer),
            .size = total_size,
        };
        const bootloader_info_blob = extended_memory.allocate_aligned(@intCast(u32, common.align_forward(@sizeOf(BootloaderInformation), page_size)), page_size, MemoryCategory.bootloader_info) catch @panic("wtf");
        const bootloader_information = @intToPtr(*BootloaderInformation, bootloader_info_blob);
        bootloader_information.* = .{
            .memory = extended_memory,
            .rsdp_physical_address = rsdp_physical_address,
        };

        return bootloader_information;
    }
};

pub const MemoryCategory = enum {
    bootloader_info,
    page_tables,
    kernel_file,
    kernel_segments,
    kernel_segment_descriptors,
    memory_map,
    junk,

    const count = common.enum_count(@This());
};

const page_table_estimated_size = VirtualAddressSpace.needed_physical_memory_for_bootstrapping_kernel_address_space + 100 * page_size;
fn get_category_size(category_type: MemoryCategory, bytes: usize) u32 {
    return @intCast(u32, switch (category_type) {
        .junk => 20 * page_size,
        .page_tables => page_table_estimated_size,

        .bootloader_info,
        .kernel_file,
        .kernel_segments,
        .kernel_segment_descriptors,
        .memory_map,
        => bytes,
    });
}

pub const ExtendedMemory = struct {
    address: u64,
    size: u32,
    allocated: u32 = 0,
    allocator: CustomAllocator = .{
        .callback_allocate = physical_allocate,
        .callback_resize = physical_resize,
        .callback_free = physical_free,
    },
    categories: [MemoryCategory.count]CategoryBookingKeeping = [1]CategoryBookingKeeping{.{}} ** MemoryCategory.count,

    pub fn allocate(extended_memory: *ExtendedMemory, bytes: u32, category: MemoryCategory) Error!u64 {
        return extended_memory.allocate_aligned(bytes, 1, category);
    }

    pub fn allocate_aligned(extended_memory: *ExtendedMemory, bytes: u32, alignment: u29, category_type: MemoryCategory) Error!u64 {
        const category = &extended_memory.categories[@enumToInt(category_type)];
        const category_size = get_category_size(category_type, bytes);

        switch (category_type) {
            .kernel_file,
            .kernel_segments,
            .memory_map,
            .bootloader_info,
            .kernel_segment_descriptors,
            => {
                if (category.allocated != 0) @panic("static big chunks cannot be redistributed");

                if (bytes % alignment != 0) @panic("WTFFFFFFFFFFFFFFFFFFFFFFFFFFF");

                const base = extended_memory.allocated;
                const result_address = extended_memory.address + base;
                defer extended_memory.allocated += category_size;
                category.* = .{
                    .offset = base,
                    .allocated = category_size,
                    .size = category_size,
                };

                log.debug("[USER-LEVEL ALLOCATION] Address: 0x{x}. Bytes: {}. Alignment: {}. Category: {s}", .{ result_address, bytes, alignment, @tagName(category_type) });

                return result_address;
            },
            .junk, .page_tables => {
                if (category.allocated == 0) {
                    const base = extended_memory.allocated;
                    if (base + category_size > extended_memory.size) @panic("Category size too big");
                    defer extended_memory.allocated += category_size;
                    log.debug("[CATEGORY-SIZE ALLOCATION] Address: 0x{x}. Size: {}. Category: {s}", .{ extended_memory.address + base, category_size, @tagName(category_type) });

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
            log.debug("Target allocated: {}. Category size: {}", .{ target_allocated, category_size });
            log.debug("Category: {s}", .{@tagName(category_type)});
            @panic("Category size overflow");
        }

        category.allocated = target_allocated;
        const result_address = extended_memory.address + category.offset + aligned_allocated;
        log.debug("[USER-LEVEL ALLOCATION] Address: 0x{x}. Bytes: {}. Alignment: {}. Category: {s}", .{ result_address, bytes, alignment, @tagName(category_type) });
        return result_address;
    }

    const CategoryBookingKeeping = extern struct {
        offset: u32 = 0,
        allocated: u32 = 0,
        size: u32 = 0,
    };
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
};

pub fn result(src: common.SourceLocation, status: Status) void {
    uefi_error(status) catch |err| {
        panic("UEFI error {} at {s}:{}:{} in function {s}", .{ err, src.file, src.line, src.column, src.fn_name });
    };
}
pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    common.std.log.scoped(.PANIC).err(format, arguments);
    CPU.stop();
}

pub const File = struct {
    handle: *FileProtocol,
    size: u32,

    pub fn get(filesystem_root: *FileProtocol, comptime name: []const u8) File {
        var file: *FileProtocol = undefined;
        const filename = str16(name);
        result(@src(), filesystem_root.open(&file, filename, FileProtocol.efi_file_mode_read, 0));
        const file_size = blk: {
            // TODO: figure out why it is succeeding with 16 and not with 8
            var buffer: [@sizeOf(FileInfo) + @sizeOf(@TypeOf(filename)) + 0x100]u8 align(@alignOf(FileInfo)) = undefined;
            var file_info_size = buffer.len;
            result(@src(), file.getInfo(&uefi.protocols.FileInfo.guid, &file_info_size, &buffer));
            const file_info = @ptrCast(*FileInfo, &buffer);
            log.debug("Unaligned file {s} size: {}", .{ name, file_info.file_size });
            break :blk @intCast(u32, common.align_forward(file_info.file_size + page_size, page_size));
        };

        return File{
            .handle = file,
            .size = file_size,
        };
    }

    pub fn read(file: *File, memory: *ExtendedMemory, category: MemoryCategory) []u8 {
        var file_buffer = @intToPtr([*]align(page_size) u8, memory.allocate_aligned(file.size, page_size, category) catch @panic("oom"))[0..file.size];
        var size: u64 = file.size;
        result(@src(), file.handle.read(&size, file_buffer.ptr));
        assert(size != file_buffer.len);
        return file_buffer[0..size];
    }
};

pub inline fn get_system_table() *SystemTable {
    return uefi.system_table;
}

pub inline fn get_handle() Handle {
    return uefi.handle;
}

pub const Protocol = struct {
    pub fn locate(comptime ProtocolT: type, boot_services: *BootServices) Error!*ProtocolT {
        var pointer_buffer: ?*anyopaque = null;
        result(@src(), boot_services.locateProtocol(&ProtocolT.guid, null, &pointer_buffer));
        return cast(ProtocolT, pointer_buffer);
    }

    pub fn handle(comptime ProtocolT: type, boot_services: *BootServices, efi_handle: Handle) Error!*ProtocolT {
        var interface_buffer: ?*anyopaque = null;
        result(@src(), boot_services.handleProtocol(efi_handle, &ProtocolT.guid, &interface_buffer));
        return cast(ProtocolT, interface_buffer);
    }

    pub fn open(comptime ProtocolT: type, boot_services: *BootServices, efi_handle: Handle) *ProtocolT {
        var interface_buffer: ?*anyopaque = null;
        result(@src(), boot_services.openProtocol(efi_handle, &ProtocolT.guid, &interface_buffer, efi_handle, null, .{ .get_protocol = true }));
        return cast(ProtocolT, interface_buffer);
    }

    fn cast(comptime ProtocolT: type, ptr: ?*anyopaque) *ProtocolT {
        return @ptrCast(*ProtocolT, @alignCast(@alignOf(ProtocolT), ptr));
    }
};

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

pub const LoadKernelFunction = fn (bootloader_information: *BootloaderInformation, kernel_start_address: u64, cr3: arch.x86_64.registers.cr3, stack: u64, gdt_descriptor: *arch.x86_64.GDT.Descriptor) callconv(.SysV) noreturn;
