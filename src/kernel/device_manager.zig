const DeviceManager = @This();

const std = @import("../common/std.zig");

const List = @import("../common/list.zig");
const StableBuffer = List.StableBuffer;

const AHCI = @import("../drivers/ahci.zig");
const ACPI = @import("../drivers/acpi.zig");
const Disk = @import("../drivers/disk.zig");
const Filesystem = @import("../drivers/filesystem.zig");
const Graphics = @import("../drivers/graphics.zig");
const PCI = @import("../drivers/pci.zig");
const VirtualAddressSpace = @import("virtual_address_space.zig");

const drivers = switch (std.cpu.arch) {
    .x86_64 => @import("arch/x86_64/drivers.zig"),
    else => unreachable,
};

const Allocator = std.Allocator;
const log = std.log.scoped(.DeviceManager);

devices: Devices = .{},
ready: bool = false,

const Devices = struct {
    disk: Device(Disk) = .{},
    filesystem: Device(Filesystem) = .{},
    graphics_adapter: Device(Graphics) = .{},
};

fn Device(comptime T: type) type {
    return struct {
        list: std.ArrayList(*T) = .{ .items = &.{}, .capacity = 0 },
        main: u32 = 0,

        pub const Type = T;

        pub fn get_main_device(device: *@This()) *T {
            return device.list.items[device.main];
        }
    };
}

pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace) !void {
    defer device_manager.ready = true;

    try drivers.init(device_manager, virtual_address_space);

    inline for (std.fields(Devices)) |device_field| {
        const device_count = @field(device_manager.devices, device_field.name).list.items.len;
        log.debug("{s} count: {}", .{ device_field.name, device_count });
    }

    std.assert(device_manager.devices.disk.list.items.len > 0);
    std.assert(device_manager.devices.filesystem.list.items.len > 0);
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

//pub fn initialize_graphics(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace) void {
////var i: u8 = 0;
//const graphics = device_manager.get_primary(Graphics);
//const framebuffer = graphics.get_main_framebuffer();
//const pixel_count = framebuffer.get_pixel_count();
//const framebuffer_pixels = framebuffer.virtual_address.access([*]volatile u32)[0..pixel_count];
//_ = framebuffer_pixels;
////std.log.scoped(.Main).debug("Pixels: {}", .{pixel_count});
////while (true) : (i +%= 1) {
////for (framebuffer_pixels) |*pixel| {
////pixel.* = (@as(u32, i) << 24) | (@as(u32, i) << 16) | (@as(u32, i) << 8) | i;
////}
////}

////const fs = device_manager.get_primary(Filesystem);
////const font_file = fs.read_file(virtual_address_space, "FiraSans-Regular.otf") catch unreachable;
////graphics.load_font(font_file, .otf);
////unreachable;
//}
