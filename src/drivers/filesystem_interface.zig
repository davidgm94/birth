const std = @import("../common/std.zig");
const Allocator = std.Allocator;

const Drivers = @import("common.zig");
const DiskInterface = @import("disk_interface.zig");
const Type = Drivers.FilesystemDriverType;

const Driver = @This();

type: Type,
disk: *DiskInterface,
/// At the moment, the memory returned by the filesystem driver is constant
callback_read_file: ?ReadFileCallback,
callback_write_file: ?WriteFileCallback,

pub fn read_file(driver: *Driver, allocator: Allocator, filename: []const u8, extra_context: ?*anyopaque) ReadError![]const u8 {
    if (driver.callback_read_file) |read_file_callback| {
        return try read_file_callback(driver, allocator, filename, extra_context);
    } else {
        return ReadError.unsupported;
    }
}

pub fn write_file(driver: *Driver, allocator: Allocator, filename: []const u8, file_content: []const u8, extra_context: ?*anyopaque) WriteError!void {
    if (driver.callback_write_file) |write_file_callback| {
        return try write_file_callback(driver, allocator, filename, file_content, extra_context);
    } else {
        return WriteError.unsupported;
    }
}

const ReadFileCallback = *const fn (driver: *Driver, allocator: Allocator, name: []const u8, extra_context: ?*anyopaque) ReadError![]const u8;
const WriteFileCallback = *const fn (driver: *Driver, allocator: Allocator, filename: []const u8, file_content: []const u8, extra_context: ?*anyopaque) WriteError!void;

pub const InitializationParameters = struct {
    filesystem_type: Type,
    disk: *DiskInterface,
    callback_read_file: ?ReadFileCallback,
    callback_write_file: ?WriteFileCallback,
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
