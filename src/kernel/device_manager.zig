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
const log = std.log.scoped(.DeviceManager);

devices: Devices = .{},
main_storage: u32 = 0,
ready: bool = false,

const Devices = struct {
    disk: std.ArrayList(*Disk) = .{ .items = &.{}, .capacity = 0 },
    filesystem: std.ArrayList(*Filesystem) = .{ .items = &.{}, .capacity = 0 },
};

pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace) !void {
    defer device_manager.ready = true;

    try drivers.init(device_manager, virtual_address_space);

    inline for (std.fields(Devices)) |device_field| {
        const device_count = @field(device_manager.devices, device_field.name).items.len;
        log.debug("{s} count: {}", .{ device_field.name, device_count });
    }

    std.assert(device_manager.devices.disk.items.len > 0);
    std.assert(device_manager.devices.filesystem.items.len > 0);
}

pub fn register_filesystem(device_manager: *DeviceManager, allocator: std.Allocator, filesystem: *Filesystem) !void {
    log.debug("Registered new {} filesystem with {} drive", .{ filesystem.interface.type, filesystem.interface.disk.type });
    try device_manager.devices.filesystem.append(allocator, filesystem);
}

pub fn register_disk(device_manager: *DeviceManager, allocator: std.Allocator, disk: *Disk) !void {
    log.debug("Registered new {} disk", .{disk.interface.type});
    try device_manager.devices.disk.append(allocator, disk);
}

pub fn get_main_storage(device_manager: *DeviceManager) *Filesystem {
    return device_manager.devices.filesystem.items[device_manager.main_storage];
}
