const std = @import("../common/std.zig");
const Allocator = std.Allocator;

const Drivers = @import("common.zig");
const Disk = @import("disk.zig");
const Type = Drivers.FilesystemDriverType;

type: Type,
disk: *Disk,
/// At the moment, the memory returned by the filesystem driver is constant
read_file: fn (driver: *Driver, allocator: Allocator, special_context: u64, name: []const u8) []const u8,
write_new_file: fn (driver: *Driver, allocator: Allocator, special_context: u64, filename: []const u8, file_content: []const u8) void,

pub const InitializationError = error{
    allocation_failure,
};

pub var drivers: std.ArrayList(*Driver) = undefined;

pub fn Driver(comptime DriverT: type) type {
    _ = DriverT;
}
