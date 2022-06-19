const kernel = @import("../kernel/kernel.zig");
const log = kernel.log.scoped(.PCIDevice);
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

base_virtual_addresses: [6]kernel.Virtual.Address,
base_physical_addresses: [6]kernel.Physical.Address,
base_addresses_size: [6]u64,
base_addresses: [6]u32,

//uint8_t  *baseAddressesVirtual[6];
//uintptr_t baseAddressesPhysical[6];
//size_t    baseAddressesSizes[6];

//uint32_t baseAddresses[6];

pub fn read_config(device: *Device, comptime T: type, offset: u8, comptime privilege_level: PrivilegeLevel) T {
    kernel.assert(@src(), privilege_level == .kernel);
    return kernel.arch.pci_read_config(T, device.bus, device.slot, device.function, offset);
}

pub fn write_config(device: *Device, comptime T: type, value: T, offset: u8, comptime privilege_level: PrivilegeLevel) void {
    kernel.assert(@src(), privilege_level == .kernel);
    return kernel.arch.pci_write_config(T, value, device.bus, device.slot, device.function, offset);
}

pub const Features = kernel.Bitflag(false, enum(u64) {
    bar0 = 0,
    bar1 = 1,
    bar2 = 2,
    bar3 = 3,
    bar4 = 4,
    bar5 = 5,
    interrupts = 8,
    busmastering_dma = 9,
    memory_space_access = 10,
    io_port_access = 11,
});

pub fn enable_features(device: *Device, features: Features) bool {
    var config = device.read_config(u32, 4, .kernel);
    if (features.contains(.interrupts)) config &= ~@as(u32, 1 << 10);
    if (features.contains(.busmastering_dma)) config |= 1 << 2;
    if (features.contains(.memory_space_access)) config |= 1 << 1;
    if (features.contains(.io_port_access)) config |= 1 << 0;
    device.write_config(u32, config, 4, .kernel);

    if (device.read_config(u32, 4, .kernel) != config) {
        return false;
    }

    for (device.base_addresses) |*base_address_ptr, i| {
        if (~features.bits & (@as(u64, 1) << @intCast(u3, i)) != 0) continue;
        const base_address = base_address_ptr.*;
        if (base_address & 1 != 0) continue; // BAR is an IO port

        if (base_address & 0b1000 == 0) {
            // TODO: not prefetchable
        }

        const is_size_64 = base_address & 0b100 != 0;

        var address: u64 = 0;
        var size: u64 = 0;

        if (is_size_64) {
            device.write_config(u32, kernel.max_int(u32), 0x10 + 4 * @intCast(u8, i), .kernel);
            device.write_config(u32, kernel.max_int(u32), 0x10 + 4 * @intCast(u8, i + 1), .kernel);
            size = device.read_config(u32, 0x10 + 4 * @intCast(u8, i), .kernel);
            size |= @intCast(u64, device.read_config(u32, 0x10 + 4 * @intCast(u8, i + 1), .kernel)) << 32;
            device.write_config(u32, base_address, 0x10 + 4 * @intCast(u8, i), .kernel);
            device.write_config(u32, device.base_addresses[i + 1], 0x10 + 4 * @intCast(u8, i + 1), .kernel);
            address = base_address;
            address |= @intCast(u64, device.base_addresses[i + 1]) << 32;
        } else {
            device.write_config(u32, kernel.max_int(u32), 0x10 + 4 * @intCast(u8, i), .kernel);
            size = device.read_config(u32, 0x10 + 4 * @intCast(u8, i), .kernel);
            size |= @as(u64, kernel.max_int(u32)) << 32;
            device.write_config(u32, base_address, 0x10 + 4 * @intCast(u8, i), .kernel);
            address = base_address;
        }

        if (size == 0 or address == 0) return false;
        log.debug("Address: 0x{x}. Size: {}", .{ address, size });
        size &= ~@as(u64, 0xf);
        size = ~size + 1;
        address &= ~@as(u64, 0xf);
        log.debug("Address: 0x{x}. Size: {}", .{ address, size });

        device.base_virtual_addresses[i] = kernel.address_space.allocate_and_map(size, kernel.Virtual.AddressSpace.Flags.from_flags(&.{
            .cache_disable,
        })) orelse @panic("allocation failed");
        device.base_physical_addresses[i] = kernel.Physical.Address.new(address);
        device.base_addresses_size[i] = size;
    }

    return true;
}
