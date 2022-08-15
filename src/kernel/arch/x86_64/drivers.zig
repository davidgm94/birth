const std = @import("../../../common/std.zig");

const AHCI = @import("../../../drivers/ahci.zig");
const ACPI = @import("../../../drivers/acpi.zig");
const DeviceManager = @import("../../device_manager.zig");
const kernel = @import("../../kernel.zig");
const PCI = @import("../../../drivers/pci.zig");
const PhysicalAddress = @import("../../physical_address.zig");
const x86_64 = @import("common.zig");
const VirtualAddressSpace = @import("../../virtual_address_space.zig");

const log = std.log.scoped(.Drivers);

pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace) !void {
    try ACPI.init(virtual_address_space, PhysicalAddress.new(x86_64.rsdp_physical_address));
    try PCI.init(device_manager, virtual_address_space, &child_drivers);
    //try AHCI.init(device_manager, virtual_address_space, &PCI.controller);
}

pub const child_drivers = [_]ChildDriver{
    AHCI,
};

const ChildDriver = type;

//const InitCallback = fn (comptime ParentDevice: type, comptime Controller: type) type {
//(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace, parent_device: *ParentDevice)
