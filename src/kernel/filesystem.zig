const Driver = @This();

const common = @import("common");
const Allocator = common.CustomAllocator;
pub const Type = common.FilesystemDriverType;

const RNU = @import("RNU");
const Disk = RNU.Disk;

type: Type,
disk: *Disk,
/// At the moment, the memory returned by the filesystem driver is constant
callback_read_file: *const ReadFile,
callback_write_file: *const WriteFile,

pub fn read_file(driver: *Driver, allocator: Allocator, filename: []const u8, extra_context: ?*anyopaque) ReadError![]const u8 {
    return try driver.callback_read_file(driver, allocator, filename, extra_context);
}

pub fn write_file(driver: *Driver, allocator: Allocator, filename: []const u8, file_content: []const u8, extra_context: ?*anyopaque) WriteError!void {
    if (driver.callback_write_file) |write_file_callback| {
        return try write_file_callback(driver, allocator, filename, file_content, extra_context);
    } else {
        return WriteError.unsupported;
    }
}

const ReadFile = fn (driver: *Driver, allocator: Allocator, name: []const u8, extra_context: ?*anyopaque) ReadError![]const u8;
const WriteFile = fn (driver: *Driver, allocator: Allocator, filename: []const u8, file_content: []const u8, extra_context: ?*anyopaque) WriteError!void;

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

pub const ReadError = error{
    unsupported,
    failed,
};

pub const WriteError = error{
    unsupported,
    failed,
};
