const Disk = @This();

const DeviceManager = @import("../kernel/device_manager.zig");
const DiskInterface = @import("disk_interface.zig");
const Drivers = @import("common.zig");
const VirtualAddressSpace = @import("../kernel/virtual_address_space.zig");

pub const Type = DiskInterface.Type;

interface: DiskInterface,

pub const Work = DiskInterface.Work;

pub const Operation = DiskInterface.Operation;

pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace, disk: *Disk, comptime maybe_driver_tree: ?[]const Drivers.Tree) !void {
    try device_manager.register_disk(virtual_address_space.heap.allocator, disk);

    if (maybe_driver_tree) |driver_tree| {
        inline for (driver_tree) |driver_node| {
            try driver_node.type.init(device_manager, virtual_address_space, disk, driver_node.children);
        }
    }
}
