const DeviceManager = @This();

const common = @import("common");
const Allocator = common.Allocator;
const ArrayList = common.ArrayList;
const assert = common.assert;
const fields = common.fields;
const log = common.log.scoped(.DeviceManager);

const RNU = @import("RNU");
const Disk = RNU.Disk;
const Filesystem = RNU.Filesystem;
const Graphics = RNU.Graphics;
const VirtualAddressSpace = RNU.VirtualAddressSpace;

const arch = @import("arch");

devices: Devices = .{},
ready: bool = false,

const Devices = struct {
    disk: Device(Disk) = .{},
    filesystem: Device(Filesystem) = .{},
    graphics_adapter: Device(Graphics) = .{},
};

fn Device(comptime T: type) type {
    return struct {
        list: ArrayList(*T) = .{ .items = &.{}, .capacity = 0 },
        main: u32 = 0,

        pub const Type = T;

        pub fn get_main_device(device: *@This()) *T {
            return device.list.items[device.main];
        }
    };
}

pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace) !void {
    defer device_manager.ready = true;

    try arch.drivers.init(device_manager, virtual_address_space);

    inline for (fields(Devices)) |device_field| {
        const device_count = @field(device_manager.devices, device_field.name).list.items.len;
        log.debug("{s} count: {}", .{ device_field.name, device_count });
    }

    assert(device_manager.devices.disk.list.items.len > 0);
    assert(device_manager.devices.filesystem.list.items.len > 0);
}

pub fn register(device_manager: *DeviceManager, comptime DeviceT: type, allocator: Allocator, new_device: *DeviceT) !void {
    defer log.debug("Registered new {} device", .{DeviceT});
    switch (DeviceT) {
        Filesystem => try device_manager.devices.filesystem.list.append(allocator, new_device),
        Disk => try device_manager.devices.disk.list.append(allocator, new_device),
        Graphics => try device_manager.devices.graphics_adapter.list.append(allocator, new_device),
        else => @compileError("Unknown device type"),
    }
}

pub fn get_primary(device_manager: *DeviceManager, comptime DeviceT: type) *DeviceT {
    return switch (DeviceT) {
        Filesystem => device_manager.devices.filesystem.list.items[device_manager.devices.filesystem.main],
        Disk => device_manager.devices.disk.list.items[device_manager.devices.disk.main],
        Graphics => device_manager.devices.graphics_adapter.list.items[device_manager.devices.graphics_adapter.main],
        else => @compileError("Unknown device type"),
    };
}

pub fn get_primary_graphics(device_manager: *DeviceManager) *Graphics {
    return device_manager.get_primary(Graphics);
}
