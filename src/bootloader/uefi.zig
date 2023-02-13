const lib = @import("../lib.zig");
const alignForward = lib.alignForward;
const assert = lib.assert;
const CustomAllocator = lib.CustomAllocator;
const log = lib.log.scoped(.UEFI);
const uefi = lib.uefi;

pub const BootServices = uefi.tables.BootServices;
pub const ConfigurationTable = uefi.tables.ConfigurationTable;
pub const Error = Status.EfiError;
pub const FileInfo = uefi.protocols.FileInfo;
pub const FileProtocol = uefi.protocols.FileProtocol;
pub const GraphicsOutputProtocol = uefi.protocols.GraphicsOutputProtocol;
pub const LoadedImageProtocol = uefi.protocols.LoadedImageProtocol;
pub const Handle = uefi.Handle;
pub const MemoryDescriptor = uefi.tables.MemoryDescriptor;
pub const SimpleFilesystemProtocol = uefi.protocols.SimpleFileSystemProtocol;
pub const Status = uefi.Status;
pub const SystemTable = uefi.tables.SystemTable;
pub const UEFIError = Status.err;

const str16 = lib.std.unicode.utf8ToUtf16LeStringLiteral;

pub const page_size = 0x1000;
pub const page_shifter = lib.arch.page_shifter(page_size);

const privileged = @import("../privileged.zig");
const PhysicalAddress = privileged.PhysicalAddress;
const VirtualAddress = privileged.VirtualAddress;
const VirtualAddressSpace = privileged.VirtualAddressSpace;
const VirtualMemoryRegion = privileged.VirtualMemoryRegion;
const stopCPU = privileged.arch.stopCPU;
pub const panic = privileged.panic;

pub fn result(src: lib.SourceLocation, status: Status) void {
    UEFIError(status) catch |err| {
        panic("UEFI error {} at {s}:{}:{} in function {s}", .{ err, src.file, src.line, src.column, src.fn_name });
    };
}

pub const File = struct {
    handle: *FileProtocol,
    size: u32,

    pub fn get(filesystem_root: *FileProtocol, name: []const u8) !File {
        var file: *FileProtocol = undefined;
        var name_buffer: [256:0]u16 = undefined;
        const length = try lib.unicode.utf8ToUtf16Le(&name_buffer, name);
        name_buffer[length] = 0;
        const filename = name_buffer[0..length :0];
        try UEFIError(filesystem_root.open(&file, filename, FileProtocol.efi_file_mode_read, 0));
        const file_size = blk: {
            // TODO: figure out why it is succeeding with 16 and not with 8
            var buffer: [@sizeOf(FileInfo) + @sizeOf(@TypeOf(filename)) + 0x100]u8 align(@alignOf(FileInfo)) = undefined;
            var file_info_size = buffer.len;
            try UEFIError(file.getInfo(&uefi.protocols.FileInfo.guid, &file_info_size, &buffer));
            const file_info = @ptrCast(*FileInfo, &buffer);
            log.debug("Unaligned file {s} size: {}", .{ name, file_info.file_size });
            break :blk @intCast(u32, alignForward(file_info.file_size + page_size, page_size));
        };

        return File{
            .handle = file,
            .size = file_size,
        };
    }

    pub fn read(file: File, buffer: []u8) []u8 {
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

//pub const LoadKernelFunction = fn (bootloader_information: *BootloaderInformation, kernel_start_address: u64, cr3: privileged.arch.x86_64.registers.cr3, stack: u64, gdt_descriptor: *privileged.arch.x86_64.GDT.Descriptor) callconv(.SysV) noreturn;
