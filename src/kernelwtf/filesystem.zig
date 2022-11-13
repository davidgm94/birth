const Driver = @This();

const common = @import("common");
const Allocator = common.CustomAllocator;
pub const Type = common.Filesystem.Type;
pub const WriteError = common.Filesystem.WriteError;
pub const ReadError = common.Filesystem.ReadError;

const rise = @import("rise");
const DeviceManager = rise.DeviceManager;
const Disk = rise.Disk;
const VirtualAddressSpace = rise.VirtualAddressSpace;

type: Type,
disk: *Disk,
/// At the moment, the memory returned by the filesystem driver is constant
callback_read_file: *const ReadFile,
callback_write_file: *const WriteFile,

pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace, filesystem: *Driver) !void {
    try device_manager.register(Driver, virtual_address_space.heap.allocator.get_allocator(), filesystem);
}

pub fn read_file(driver: *Driver, virtual_address_space: *VirtualAddressSpace, filename: []const u8) ReadError![]const u8 {
    return try driver.callback_read_file(driver, virtual_address_space, filename);
}

pub fn write_file(driver: *Driver, virtual_address_space: *VirtualAddressSpace, filename: []const u8, file_content: []const u8) WriteError!void {
    if (driver.callback_write_file) |write_file_callback| {
        return try write_file_callback(driver, virtual_address_space, filename, file_content);
    } else {
        return WriteError.unsupported;
    }
}

const ReadFile = fn (driver: *Driver, virtual_address_space: *VirtualAddressSpace, name: []const u8) ReadError![]const u8;
const WriteFile = fn (driver: *Driver, virtual_address_space: *VirtualAddressSpace, filename: []const u8, file_content: []const u8) WriteError!void;

pub const InitializationParameters = struct {
    filesystem_type: Type,
    disk: *Disk,
    callback_read_file: ReadFile,
    callback_write_file: WriteFile,
};

pub fn new(parameters: InitializationParameters) Driver {
    return Driver{
        .type = parameters.filesystem_type,
        .disk = parameters.disk,
        .callback_read_file = parameters.callback_read_file,
        .callback_write_file = parameters.callback_write_file,
    };
}

pub const InitializationError = error{
    allocation_failure,
};
