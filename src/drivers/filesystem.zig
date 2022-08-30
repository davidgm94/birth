const Filesystem = @This();

const std = @import("../common/std.zig");

const DeviceManager = @import("../kernel/device_manager.zig");
const Drivers = @import("common.zig");
const FilesystemInterface = @import("filesystem_interface.zig");
const VirtualAddressSpace = @import("../kernel/virtual_address_space.zig");

const Allocator = std.Allocator;
const Type = FilesystemInterface.FilesystemDriverType;

interface: FilesystemInterface,

pub const ReadFileCallback = FilesystemInterface.ReadFileCallback;
pub const WriteFileCallback = FilesystemInterface.WriteFileCallback;

pub const ReadError = FilesystemInterface.ReadError;
pub const WriteError = FilesystemInterface.WriteError;

pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace, filesystem: *Filesystem, comptime maybe_driver_tree: ?[]const Drivers.Tree) !void {
    try device_manager.register(Filesystem, virtual_address_space.heap.allocator, filesystem);
    if (maybe_driver_tree) |driver_tree| {
        inline for (driver_tree) |driver_node| {
            try driver_node.type.init(device_manager, virtual_address_space, filesystem, driver_node.children);
        }
    }
}

//const ReadFileCallback = *const fn (driver: *Driver, allocator: Allocator, name: []const u8, extra_context: ?*anyopaque) []const u8;
//const WriteFileCallback = *const fn (driver: *Driver, allocator: Allocator, filename: []const u8, file_content: []const u8, extra_context: ?*anyopaque) void;

pub fn read_file(filesystem: *Filesystem, virtual_address_space: *VirtualAddressSpace, filename: []const u8) ReadError![]const u8 {
    if (filesystem.interface.callback_read_file) |read_file_callback| {
        return read_file_callback(&filesystem.interface, virtual_address_space.heap.allocator, filename, virtual_address_space);
    } else {
        return ReadError.unsupported;
    }
}

pub fn write_file(filesystem: *Filesystem, virtual_address_space: *VirtualAddressSpace, filename: []const u8, file_content: []const u8) WriteError![]const u8 {
    if (filesystem.interface.callback_write_file) |write_file_callback| {
        return write_file_callback(&filesystem.interface, virtual_address_space.heap.allocator, filename, file_content, virtual_address_space);
    } else {
        return ReadError.unsupported;
    }
}

//type: Type,
//disk: *DiskInterface,
///// At the moment, the memory returned by the filesystem driver is constant
//read_file: ?ReadFileCallback,
//write_new_file: ?WriteFileCallback,
