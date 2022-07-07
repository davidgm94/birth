const Drivers = @import("../drivers.zig");
const Disk = Drivers.Disk;
const common = @import("../common.zig");

const TODO = common.TODO;
const log = common.log.scoped(.FS);
const Allocator = common.Allocator;
const VirtualAddressSpace = common.VirtualAddressSpace;

const Driver = @This();

const Type = enum(u32) {
    RNU = 0,
    ext2 = 1,
};

type: Type,
allocator: Allocator,
disk: *Disk,
/// At the moment, the memory returned by the filesystem driver is constant
read_file: fn (driver: *Driver, special_context: u64, name: []const u8) []const u8,
write_new_file: fn (driver: *Driver, special_context: u64, filename: []const u8, file_content: []const u8) void,

pub const InitializationError = error{
    allocation_failure,
};

pub var drivers: common.ArrayList(*Driver) = undefined;
