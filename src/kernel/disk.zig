const Disk = @This();

const common = @import("common");
const assert = common.assert;
const Allocator = common.CustomAllocator;
const log = common.log.scoped(.Disk);
pub const Type = common.DiskDriverType;

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
        assert(@bitSizeOf(Operation) == @bitSizeOf(u1));
        assert(@enumToInt(Operation.read) == 0);
        assert(@enumToInt(Operation.write) == 1);
    }
};
