const kernel = @import("root");
const DMA = kernel.drivers.DMA;
const Driver = @This();

pub const Type = enum(u32) {
    virtio = 0,
    nvme = 1,
};

sector_size: u64,
access: fn (driver: *Driver, buffer: *DMA.Buffer, disk_work: Work) u64,
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

pub var drivers: kernel.ArrayList(*Driver) = undefined;
