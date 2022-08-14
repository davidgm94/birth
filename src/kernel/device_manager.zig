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
