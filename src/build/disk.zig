const BuildDisk = @This();

const std = @import("std");
const assert = std.debug.assert;
const common = @import("../common.zig");
const drivers = @import("../drivers.zig");
const RNUFS = common.RNUFS;
const Disk = drivers.Disk;
const Allocator = common.Allocator;

const log = std.log_scoped(.build_fs);

disk: Disk,
memory: []u8,

const sector_size = 0x200;

fn access(disk: *Disk, special_context: u64, buffer: *drivers.DMA.Buffer, disk_work: Disk.Work) u64 {
    _ = disk;
    _ = special_context;
    _ = buffer;
    _ = disk_work;
    common.TODO(@src());
}

fn get_dma_buffer(disk: *Disk, allocator: Allocator, sector_count: u64) Allocator.Error!drivers.DMA.Buffer {
    _ = disk;
    _ = allocator;
    _ = sector_count;
    common.TODO(@src());
}

pub fn new(memory: []u8) BuildDisk {
    return BuildDisk{
        .disk = Disk{
            .sector_size = 0x200,
            .access = access,
            .get_dma_buffer = get_dma_buffer,
            .type = .memory,
        },
        .memory = memory,
    };
}

//pub fn read_debug(disk: MemoryDisk) void {
//var node = @ptrCast(*RNUFS.Node, @alignCast(@alignOf(RNUFS.Node), disk.bytes.ptr));
//log.debug("Node size: {}. Node name: {s}", .{ node.size, node.name });
//log.debug("First bytes:", .{});
//for (disk.bytes[sector_size .. sector_size + 0x20]) |byte, i| {
//log.debug("[{}]: 0x{x}", .{ i, byte });
//}
//}
