const BuildDisk = @This();

const assert = common.assert;
const common = @import("../common.zig");
const drivers = @import("../drivers.zig");
const RNUFS = common.RNUFS;
const Disk = drivers.Disk;
const Allocator = common.Allocator;
const VirtualAddress = common.VirtualAddress;

const log = common.log.scoped(.BuildDisk);

disk: Disk,
buffer: common.ArrayListAligned(u8, 0x1000),

fn access(disk: *Disk, special_context: u64, buffer: *drivers.DMA.Buffer, disk_work: Disk.Work) u64 {
    const build_disk = @fieldParentPtr(BuildDisk, "disk", disk);
    _ = special_context;
    const sector_size = disk.sector_size;
    log.debug("Disk work: {}", .{disk_work});
    switch (disk_work.operation) {
        .write => {
            const work_byte_size = disk_work.sector_count * sector_size;
            const byte_count = work_byte_size;
            const write_source_buffer = buffer.address.access([*]const u8)[0..byte_count];
            const disk_slice_start = disk_work.sector_offset * sector_size;
            log.debug("Disk slice start: {}. Disk len: {}", .{ disk_slice_start, build_disk.buffer.items.len });
            common.runtime_assert(@src(), disk_slice_start == build_disk.buffer.items.len);
            build_disk.buffer.appendSliceAssumeCapacity(write_source_buffer);
            build_disk.buffer.items.len = common.align_forward(build_disk.buffer.items.len, sector_size);

            return byte_count;
        },
        .read => {
            const offset = disk_work.sector_offset * sector_size;
            const bytes = disk_work.sector_count * sector_size;
            const previous_len = build_disk.buffer.items.len;

            if (offset >= previous_len or offset + bytes > previous_len) build_disk.buffer.items.len = build_disk.buffer.capacity;
            common.copy(u8, buffer.address.access([*]u8)[0..bytes], build_disk.buffer.items[offset .. offset + bytes]);
            if (offset >= previous_len or offset + bytes > previous_len) build_disk.buffer.items.len = previous_len;

            return disk_work.sector_count;
        },
    }
}

fn get_dma_buffer(disk: *Disk, allocator: Allocator, sector_count: u64) Allocator.Error!drivers.DMA.Buffer {
    const allocation_size = disk.sector_size * sector_count;
    const alignment = 0x1000;
    log.debug("DMA buffer allocation size: {}, alignment: {}", .{ allocation_size, alignment });
    const allocation_slice = try allocator.allocBytes(@intCast(u29, alignment), allocation_size, 0, 0);
    common.zero(allocation_slice);
    log.debug("Allocation address: 0x{x}", .{@ptrToInt(allocation_slice.ptr)});
    return drivers.DMA.Buffer{
        .address = VirtualAddress.new(@ptrToInt(allocation_slice.ptr)),
        .total_size = allocation_slice.len,
        .completed_size = 0,
    };
}

pub fn new(buffer: common.ArrayListAligned(u8, 0x1000)) BuildDisk {
    return BuildDisk{
        .disk = Disk{
            .sector_size = 0x200,
            .access = access,
            .get_dma_buffer = get_dma_buffer,
            .type = .memory,
        },
        .buffer = buffer,
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
