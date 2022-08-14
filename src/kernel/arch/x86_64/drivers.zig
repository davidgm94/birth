const std = @import("../../../common/std.zig");

const AHCI = @import("../../../drivers/ahci.zig");
const ACPI = @import("../../../drivers/acpi.zig");
const Disk = @import("../../../drivers/disk.zig");
const DeviceManager = @import("../../device_manager.zig");
const Filesystem = @import("../../../drivers/filesystem.zig");
const kernel = @import("../../kernel.zig");
const PCI = @import("../../../drivers/pci.zig");
const PhysicalAddress = @import("../../physical_address.zig");
const RNUFS = @import("../../../drivers/rnufs/rnufs.zig");
const VirtualAddressSpace = @import("../../virtual_address_space.zig");

const log = std.log.scoped(.Drivers);

pub fn register_main_storage() void {
    kernel.device_manager.main_storage = kernel.drivers.filesystem.items[0];
}

pub fn drivers_init(virtual_address_space: *VirtualAddressSpace) !void {
    try init_block_drivers(virtual_address_space);
    log.debug("Initialized block drivers", .{});

    try init_graphics_drivers(virtual_address_space.heap.allocator);
    log.debug("Initialized graphics drivers", .{});
}

pub fn init_block_drivers(virtual_address_space: *VirtualAddressSpace) !void {
    AHCI.drivers = try AHCI.Initialization.callback(virtual_address_space, &PCI.controller);
    std.assert(Disk.drivers.items.len > 0);
    try kernel.device_manager.add_filesystem_driver(
        RNUFS,
        virtual_address_space,
    ).init(virtual_address_space.heap.allocator, Disk.drivers.items[0]);
    // TODO: make ACPI and PCI controller standard
    // TODO: make a category for NVMe and standardize it there
    // INFO: this callback also initialize child drives
    //NVMe.driver = try NVMe.Initialization.callback(virtual_address_space, &PCI.controller);
}

pub fn init_graphics_drivers(allocator: std.Allocator) !void {
    _ = allocator;
    log.debug("TODO: initialize graphics drivers", .{});
}

pub fn prepare(virtual_address_space: *VirtualAddressSpace, rsdp: PhysicalAddress) void {
    ACPI.init(virtual_address_space, rsdp);
    PCI.init(virtual_address_space);
}
