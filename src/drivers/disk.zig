const Disk = @This();

const std = @import("../common/std.zig");

const DeviceManager = @import("../kernel/device_manager.zig");
const DiskInterface = @import("disk_interface.zig");
const Drivers = @import("common.zig");
const VirtualAddressSpace = @import("../kernel/virtual_address_space.zig");

const log = std.log.scoped(.Disk);

interface: DiskInterface,

pub const Type = DiskInterface.Type;
pub const Work = DiskInterface.Work;
pub const Operation = DiskInterface.Operation;

pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace, disk: *Disk, comptime maybe_driver_tree: ?[]const Drivers.Tree) !void {
    try device_manager.register(Disk, virtual_address_space.heap.allocator.get_allocator(), disk);

    // Look for filesystems: this can fail
    if (maybe_driver_tree) |driver_tree| {
        inline for (driver_tree) |driver_node| {
            log.debug("Looking for filesystem {}...", .{driver_node.type});
            driver_node.type.init(device_manager, virtual_address_space, disk, driver_node.children) catch |err| log.err("Failed to initialized filesystem {}: {}", .{ driver_node.type, err });
        }
    }
}
