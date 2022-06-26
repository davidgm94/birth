const kernel = @import("kernel");
const Driver = @This();

const Type = enum(u32) {
    virtio = 0,
};

type: Type,
read_callback: fn (driver: *Driver, buffer: []u8, sector_start: u64, sector_count: u64) u64,

pub var drivers: kernel.ArrayList(*Driver) = undefined;