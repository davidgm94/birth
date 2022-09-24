const Disk = @This();

const std = @import("../common/std.zig");

const DeviceManager = @import("../kernel/device_manager.zig");
const DiskInterface = @import("disk_interface.zig");
const Drivers = @import("common.zig");
const RNUFS = @import("rnufs/rnufs.zig");
const VirtualAddressSpace = @import("../kernel/virtual_address_space.zig");

const log = std.log.scoped(.Disk);

interface: DiskInterface,

pub const Type = DiskInterface.Type;
pub const Work = DiskInterface.Work;
pub const Operation = DiskInterface.Operation;

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
