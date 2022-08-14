const DeviceManager = @This();

const std = @import("../common/std.zig");

const List = @import("../common/list.zig");
const StableBuffer = List.StableBuffer;
const Disk = @import("../drivers/disk.zig");
const Filesystem = @import("../drivers/filesystem.zig");

const Allocator = std.Allocator;

disks: StableBuffer(Disk, 64),
filesystems: StableBuffer(Filesystem, 64),
main_storage: u32,

pub fn add_filesystem(device_manager: *DeviceManager, comptime Driver: type, disk: *Disk) void {
    _ = device_manager;
    _ = Driver;
    _ = disk;
    unreachable;
}

pub fn get_main_storage(device_manager: *DeviceManager) *Filesystem {
    std.assert(device_manager.filesystems.bucket_count == 1);
    const main_storage_bucket = device_manager.filesystems.first orelse @panic("wtf");
    return &main_storage_bucket.data[device_manager.main_storage];
}
