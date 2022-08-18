const Filesystem = @This();

const std = @import("../common/std.zig");

const DeviceManager = @import("../kernel/device_manager.zig");
const Drivers = @import("common.zig");
const FilesystemInterface = @import("filesystem_interface.zig");
const VirtualAddressSpace = @import("../kernel/virtual_address_space.zig");

const Allocator = std.Allocator;
const Type = FilesystemInterface.FilesystemDriverType;

interface: FilesystemInterface,

const ReadFileCallback = FilesystemInterface.ReadFileCallback;
const WriteFileCallback = FilesystemInterface.WriteFileCallback;

pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace, filesystem: *Filesystem, comptime maybe_driver_tree: ?[]const Drivers.Tree) !void {
    try device_manager.register(Filesystem, virtual_address_space.heap.allocator, filesystem);
    if (maybe_driver_tree) |driver_tree| {
        inline for (driver_tree) |driver_node| {
            try driver_node.type.init(device_manager, virtual_address_space, filesystem, driver_node.children);
        }
    }
}
