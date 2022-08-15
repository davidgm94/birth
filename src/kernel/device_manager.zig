const DeviceManager = @This();

const std = @import("../common/std.zig");

const List = @import("../common/list.zig");
const StableBuffer = List.StableBuffer;

const AHCI = @import("../drivers/ahci.zig");
const ACPI = @import("../drivers/acpi.zig");
const Disk = @import("../drivers/disk.zig");
const Filesystem = @import("../drivers/filesystem.zig");
const PCI = @import("../drivers/pci.zig");
const VirtualAddressSpace = @import("virtual_address_space.zig");

const drivers = switch (std.cpu.arch) {
    .x86_64 => @import("arch/x86_64/drivers.zig"),
    else => unreachable,
};

const Allocator = std.Allocator;

disks: std.ArrayList(*Disk) = .{ .items = &.{}, .capacity = 0 },
filesystems: std.ArrayList(*Filesystem) = .{ .items = &.{}, .capacity = 0 },
main_storage: u32 = 0,

pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace) !void {
    try drivers.init(device_manager, virtual_address_space);
}

pub fn register_filesystem(device_manager: *DeviceManager, allocator: std.Allocator, filesystem: *Filesystem) !void {
    try device_manager.filesystems.append(allocator, filesystem);
}

pub fn register_disk(device_manager: *DeviceManager, allocator: std.Allocator, disk: *Disk) !void {
    try device_manager.disks.append(allocator, disk);
}

pub fn get_main_storage(device_manager: *DeviceManager) *Filesystem {
    return device_manager.filesystems.items[device_manager.main_storage];
}
