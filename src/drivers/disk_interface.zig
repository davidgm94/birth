const DiskInterface = @This();

const std = @import("../common/std.zig");
const Drivers = @import("common.zig");
const DMA = @import("dma.zig");

pub const Type = Drivers.DiskDriverType;

type: Type,
sector_size: u64,
access: *const fn (disk_interface: *DiskInterface, buffer: *DMA.Buffer, disk_work: Work, extra_context: ?*anyopaque) u64,
get_dma_buffer: *const fn (disk_interface: *DiskInterface, allocator: std.CustomAllocator, sector_count: u64) std.Allocator.Error!DMA.Buffer,

pub const Work = struct {
    sector_offset: u64,
    sector_count: u64,
    operation: Operation,
};

pub const Operation = enum(u1) {
    read = 0,
    write = 1,

    // This is used by NVMe and AHCI
    comptime {
        std.assert(@bitSizeOf(Operation) == @bitSizeOf(u1));
        std.assert(@enumToInt(Operation.read) == 0);
        std.assert(@enumToInt(Operation.write) == 1);
    }
};
