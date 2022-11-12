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
pub const page_size = 0x1000;
pub const page_shifter = arch.page_shifter(page_size);

const privileged = @import("privileged");
const PhysicalAddress = privileged.PhysicalAddress;
const VirtualAddress = privileged.VirtualAddress;
const VirtualAddressSpace = privileged.VirtualAddressSpace;
const VirtualMemoryRegion = privileged.VirtualMemoryRegion;

pub const MemoryMap = struct {
    region: VirtualMemoryRegion,
    descriptor_size: u32 = @sizeOf(MemoryDescriptor),
    descriptor_version: u32 = 1,

    pub const SizeCounters = struct {
        counters: []u32 = &.{},

        pub fn to_higher_half(size_counters: SizeCounters) []u32 {
            return @intToPtr([*]u32, @ptrToInt(size_counters.counters.ptr) + common.config.kernel_higher_half_address)[0..size_counters.counters.len];
        }
    };

    pub fn iterator(_: MemoryMap) Iterator {
        return Iterator{};
    }

    pub fn to_higher_half(memory_map: MemoryMap) MemoryMap {
        var map = memory_map;
        map.region.address = memory_map.region.address.offset(common.config.kernel_higher_half_address);
        return map;
    }

    pub const Iterator = struct {
        offset: usize = 0,

        pub fn next(it: *Iterator, memory_map: MemoryMap) ?*MemoryDescriptor {
            if (it.offset < memory_map.region.size) {
                const descriptor_address = memory_map.region.address.value + it.offset;
                it.offset += memory_map.descriptor_size;
                return @intToPtr(*MemoryDescriptor, descriptor_address);
            }

            return null;
        }

        pub inline fn reset(it: *Iterator) void {
            it.offset = 0;
        }
    };
};

pub const BootloaderInformation = struct {
    kernel_segments: []ProgramSegment,
    memory_map: MemoryMap,
    counters: []u32,
    rsdp_physical_address: PhysicalAddress,
    kernel_file: BootstrapChunk,
    init_file: BootstrapChunk,
};

pub const BootstrapChunk = struct {
    offset: usize,
    size: usize,
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

    pub fn get(filesystem_root: *FileProtocol, comptime name: []const u8) !File {
        var file: *FileProtocol = undefined;
        const filename = str16(name);
        try uefi_error(filesystem_root.open(&file, filename, FileProtocol.efi_file_mode_read, 0));
        const file_size = blk: {
            // TODO: figure out why it is succeeding with 16 and not with 8
            var buffer: [@sizeOf(FileInfo) + @sizeOf(@TypeOf(filename)) + 0x100]u8 align(@alignOf(FileInfo)) = undefined;
            var file_info_size = buffer.len;
            try uefi_error(file.getInfo(&uefi.protocols.FileInfo.guid, &file_info_size, &buffer));
            const file_info = @ptrCast(*FileInfo, &buffer);
            log.debug("Unaligned file {s} size: {}", .{ name, file_info.file_size });
            break :blk @intCast(u32, common.align_forward(file_info.file_size + page_size, page_size));
        };

        return File{
            .handle = file,
            .size = file_size,
        };
    }

    pub fn read(file: *File, buffer: []u8) []u8 {
        var size: u64 = file.size;
        result(@src(), file.handle.read(&size, buffer.ptr));
        assert(size != buffer.len);
        return buffer[0..size];
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
