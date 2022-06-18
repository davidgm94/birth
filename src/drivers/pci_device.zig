const kernel = @import("../kernel/kernel.zig");
const Device = @This();
const Controller = @import("pci.zig");

const PrivilegeLevel = kernel.PrivilegeLevel;

device_id: u32,
subsystem_id: u32,
domain: u32,
class_code: u8,
subclass_code: u8,
prog_if: u8,
bus: u8,
slot: u8,
function: u8,
interrupt_pin: u8,
interrupt_line: u8,

base_addresses: [6]u32,

//uint8_t  *baseAddressesVirtual[6];
//uintptr_t baseAddressesPhysical[6];
//size_t    baseAddressesSizes[6];

//uint32_t baseAddresses[6];

pub fn read_config(device: *Device, comptime T: type, offset: u8, comptime privilege_level: PrivilegeLevel) T {
    kernel.assert(@src(), privilege_level == .kernel);
    return kernel.arch.pci_read_config(T, device.bus, device.slot, device.function, offset);
}

pub fn write_config(device: *Device, comptime T: type, value: T, offset: u8, comptime privilege_level: PrivilegeLevel) T {
    kernel.assert(@src(), privilege_level == .kernel);
    return kernel.arch.pci_write_config(T, value, device.bus, device.slot, device.function, offset);
}
