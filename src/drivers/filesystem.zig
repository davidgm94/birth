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

pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace, filesystem: *Filesystem) !void {
    try device_manager.register(Filesystem, virtual_address_space.heap.allocator.get_allocator(), filesystem);
}

//const ReadFileCallback = *const fn (driver: *Driver, allocator: Allocator, name: []const u8, extra_context: ?*anyopaque) []const u8;
//const WriteFileCallback = *const fn (driver: *Driver, allocator: Allocator, filename: []const u8, file_content: []const u8, extra_context: ?*anyopaque) void;

pub fn read_file(filesystem: *Filesystem, virtual_address_space: *VirtualAddressSpace, filename: []const u8) ReadError![]const u8 {
    return try filesystem.interface.read_file(virtual_address_space.heap.allocator, filename, virtual_address_space);
}

pub fn write_file(filesystem: *Filesystem, virtual_address_space: *VirtualAddressSpace, filename: []const u8, file_content: []const u8) WriteError![]const u8 {
    return try filesystem.interface.write_file(virtual_address_space, filename, file_content);
}

//type: Type,
//disk: *DiskInterface,
///// At the moment, the memory returned by the filesystem driver is constant
//read_file: ?ReadFileCallback,
//write_new_file: ?WriteFileCallback,
