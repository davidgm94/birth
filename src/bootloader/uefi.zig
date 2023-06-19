const lib = @import("lib");
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
pub const Try = Status.err;

const str16 = lib.std.unicode.utf8ToUtf16LeStringLiteral;

pub const page_size = 0x1000;
pub const page_shifter = lib.arch.page_shifter(page_size);

const privileged = @import("privileged");
const PhysicalAddress = privileged.PhysicalAddress;
const VirtualAddress = privileged.VirtualAddress;
const VirtualMemoryRegion = privileged.VirtualMemoryRegion;
const stopCPU = privileged.arch.stopCPU;

pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    privileged.arch.disableInterrupts();
    lib.log.scoped(.PANIC).err(format, arguments);
    privileged.arch.stopCPU();
}

pub fn result(src: lib.SourceLocation, status: Status) void {
    Try(status) catch |err| {
        panic("UEFI error {} at {s}:{}:{} in function {s}", .{ err, src.file, src.line, src.column, src.fn_name });
    };
}

pub inline fn getSystemTable() *SystemTable {
    return uefi.system_table;
}

pub inline fn getHandle() Handle {
    return uefi.handle;
}

pub const Protocol = struct {
    pub fn locate(comptime ProtocolT: type, boot_services: *BootServices) !*ProtocolT {
        var pointer_buffer: ?*anyopaque = null;
        try Try(boot_services.locateProtocol(&ProtocolT.guid, null, &pointer_buffer));
        return cast(ProtocolT, pointer_buffer);
    }

    pub fn handle(comptime ProtocolT: type, boot_services: *BootServices, efi_handle: Handle) !*ProtocolT {
        var interface_buffer: ?*anyopaque = null;
        try Try(boot_services.handleProtocol(efi_handle, &ProtocolT.guid, &interface_buffer));
        return cast(ProtocolT, interface_buffer);
    }

    pub fn open(comptime ProtocolT: type, boot_services: *BootServices, efi_handle: Handle) !*ProtocolT {
        var interface_buffer: ?*anyopaque = null;
        try Try(boot_services.openProtocol(efi_handle, &ProtocolT.guid, &interface_buffer, efi_handle, null, .{ .get_protocol = true }));
        return cast(ProtocolT, interface_buffer);
    }

    fn cast(comptime ProtocolT: type, ptr: ?*anyopaque) *ProtocolT {
        return @as(*ProtocolT, @ptrCast(@alignCast(@alignOf(ProtocolT), ptr)));
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
