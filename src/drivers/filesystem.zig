const Drivers = @import("../drivers.zig");
const Disk = Drivers.Disk;
const common = @import("../common.zig");

const TODO = common.TODO;
const log = common.log.scoped(.FS);
const Allocator = common.Allocator;

const Driver = @This();

const Type = enum(u32) {
    RNU = 0,
    ext2 = 1,
};

type: Type,
allocator: Allocator,
disk: *Disk,
/// At the moment, the memory returned by the filesystem driver is constant
read_file_callback: fn read(driver: *Driver, name: []const u8) []const u8,

pub const InitializationError = error{
    allocation_failure,
};

pub var drivers: common.ArrayList(*Driver) = undefined;
