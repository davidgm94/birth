const BuildDisk = @This();

const assert = common.assert;
const common = @import("../common.zig");
const drivers = @import("../drivers.zig");
const RNUFS = common.RNUFS;
const Disk = drivers.Disk;
const Allocator = common.Allocator;

const log = common.log_scoped(.build_fs);

disk: Disk,
memory: []u8,

const sector_size = 0x200;

fn access(disk: *Disk, special_context: u64, buffer: *drivers.DMA.Buffer, disk_work: Disk.Work) u64 {
    _ = special_context;
    switch (disk_work.operation) {
        .write => {
            const work_byte_size = disk_work.sector_count * disk.sector_size;
            const byte_count = common.min(work_byte_size, buffer.total_size);
            const write_source_buffer = buffer.address.access([*]const u8)[0..byte_count];
            const disk_slice_start = disk_work.sector_offset * disk.sector_size;
            const disk_slice_end = disk_slice_start + byte_count;
            const write_destination_buffer = @fieldParentPtr(BuildDisk, "disk", disk).memory[disk_slice_start..disk_slice_end];
            common.copy(u8, write_destination_buffer, write_source_buffer);

            return byte_count;
        },
        .read => unreachable,
    }
}

fn get_dma_buffer(disk: *Disk, allocator: Allocator, sector_count: u64) Allocator.Error!drivers.DMA.Buffer {
    const allocation_size = disk.sector_size * sector_count;
    const allocation_slice = try allocator.allocBytes(@intCast(u29, disk.sector_size), allocation_size, 0, 0);
    return drivers.DMA.Buffer{
        .address = common.VirtualAddress.new(@ptrToInt(allocation_slice.ptr)),
        .total_size = allocation_slice.len,
        .completed_size = 0,
    };
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
