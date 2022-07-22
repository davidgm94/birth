const common = @import("../common.zig");
const Drivers = @import("../drivers.zig");
const DMA = Drivers.DMA;

const Driver = @This();

pub const Type = common.DiskDriverType;

sector_size: u64,
access: fn (driver: *Driver, special_context: u64, buffer: *DMA.Buffer, disk_work: Work) u64,
get_dma_buffer: fn (driver: *Driver, allocator: common.Allocator, sector_count: u64) common.Allocator.Error!DMA.Buffer,

type: Type,

pub const Work = struct {
    sector_offset: u64,
    sector_count: u64,
    operation: Operation,
};

pub const Operation = enum {
    read,
    write,
};

pub var drivers: common.ArrayList(*Driver) = undefined;
