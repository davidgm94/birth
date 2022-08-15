const std = @import("../common/std.zig");
const Allocator = std.Allocator;

const Drivers = @import("common.zig");
const DiskInterface = @import("disk_interface.zig");
const Type = Drivers.FilesystemDriverType;

const Driver = @This();

type: Type,
disk: *DiskInterface,
/// At the moment, the memory returned by the filesystem driver is constant
read_file: ?ReadFileCallback,
write_new_file: ?WriteFileCallback,

const ReadFileCallback = fn (driver: *Driver, allocator: Allocator, name: []const u8, extra_context: ?*anyopaque) []const u8;
const WriteFileCallback = fn (driver: *Driver, allocator: Allocator, filename: []const u8, file_content: []const u8, extra_context: ?*anyopaque) void;

pub const InitializationParameters = struct {
    filesystem_type: Type,
    disk: *DiskInterface,
    read_file_callback: ?ReadFileCallback,
    write_file_callback: ?WriteFileCallback,
};

pub fn new(parameters: InitializationParameters) Driver {
    return Driver{
        .type = parameters.filesystem_type,
        .disk = parameters.disk,
        .read_file = parameters.read_file_callback,
        .write_new_file = parameters.write_file_callback,
    };
}

pub const InitializationError = error{
    allocation_failure,
};
