const Disk = @This();

const common = @import("common");
const assert = common.assert;
const Allocator = common.CustomAllocator;
const log = common.log.scoped(.Disk);
pub const Type = common.Disk.Type;
pub const Work = common.Disk.Work;
pub const Operation = common.Disk.Operation;

const RNU = @import("RNU");
const DeviceManager = RNU.DeviceManager;
const DMA = RNU.Drivers.DMA;
const VirtualAddressSpace = RNU.VirtualAddressSpace;

const RNUFS = @import("../drivers/rnufs/rnufs.zig");

type: Type,
sector_size: u64,
callback_access: *const fn (disk: *Disk, buffer: *DMA.Buffer, disk_work: Work, extra_context: ?*anyopaque) u64,
callback_get_dma_buffer: *const fn (disk: *Disk, allocator: Allocator, sector_count: u64) Allocator.Error!DMA.Buffer,

pub fn access(disk: *Disk, buffer: *DMA.Buffer, disk_work: Work, extra_context: ?*anyopaque) u64 {
    return disk.callback_access(disk, buffer, disk_work, extra_context);
}

pub fn get_dma_buffer(disk: *Disk, allocator: Allocator, sector_count: u64) Allocator.Error!DMA.Buffer {
    return try disk.callback_get_dma_buffer(disk, allocator, sector_count);
}

pub const Filesystems = .{RNUFS};

pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace, disk: *Disk) !void {
    try device_manager.register(Disk, virtual_address_space.heap.allocator.get_allocator(), disk);

    // TODO: look for more filesystems. Detect filesystem here
    // Look for filesystems: this can fail
    inline for (Filesystems) |Filesystem| {
        log.debug("Looking for filesystem {}...", .{Filesystem});
        Filesystem.init(device_manager, virtual_address_space, disk) catch |err| log.err("Failed to initialized filesystem {}: {}", .{ Filesystem, err });
    }
}
