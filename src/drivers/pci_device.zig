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

pub inline fn read_config(device: *Device, comptime T: type, offset: u8, comptime privilege_level: PrivilegeLevel) T {
    kernel.assert(@src(), privilege_level == .kernel);
    return kernel.arch.pci_read_config(T, device.bus, device.slot, device.function, offset);
}

pub inline fn write_config(device: *Device, comptime T: type, value: T, offset: u8, comptime privilege_level: PrivilegeLevel) void {
    kernel.assert(@src(), privilege_level == .kernel);
    return kernel.arch.pci_write_config(T, value, device.bus, device.slot, device.function, offset);
}

pub inline fn read_bar(device: *Device, comptime T: type, index: u64, offset: u64) T {
    const base_address = device.base_addresses[index];
    log.debug("Base address: 0x{x}", .{base_address});
    if (T != u64) {
        if (base_address & 1 != 0) {
            log.debug("Using base address for read", .{});
            const port = @intCast(u16, (base_address & ~@as(u32, 3)) + offset);
            return kernel.arch.io_read(T, port);
        } else {
            log.debug("Using base virtual address for read", .{});
            return device.base_virtual_addresses[index].offset(offset).access(*volatile T).*;
        }
    } else {
        if (base_address & 1 != 0) {
            log.debug("Using base address for read", .{});
            return device.read_bar(u32, index, offset) | (@intCast(u64, device.read_bar(u64, index, offset + @sizeOf(u32))) << 32);
        } else {
            log.debug("Using base virtual address for read", .{});
            return device.base_virtual_addresses[index].offset(offset).access(*volatile T).*;
        }
    }
}

pub inline fn write_bar(device: *Device, comptime T: type, index: u64, offset: u64, value: T) void {
    const base_address = device.base_addresses[index];
    log.debug("Base address 0x{x}", .{base_address});
    if (T != u64) {
        if (base_address & 1 != 0) {
            const port = @intCast(u16, (base_address & ~@as(@TypeOf(base_address), 3)) + offset);
            log.debug("Writing to port 0x{x}", .{port});
            kernel.arch.io_write(T, port, value);
        } else {
            log.debug("index: {}", .{index});
            const virtual_address = device.base_virtual_addresses[index].offset(offset);
            log.debug("Virtual address: 0x{x}", .{virtual_address.value});
            virtual_address.access(*volatile T).* = value;
        }
    } else {
        if (base_address & 1 != 0) {
            log.debug("here?", .{});
            device.write_bar(u32, offset, @truncate(u32, value));
            device.write_bar(u32, offset + @sizeOf(u32), @truncate(u32, value >> 32));
        } else {
            log.debug("here?", .{});
            device.base_virtual_addresses[index].offset(offset).access(*volatile T).* = value;
        }
    }
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
    log.debug("Enabling features for device {}", .{device});
    var config = device.read_config(u32, 4, .kernel);
    if (features.contains(.interrupts)) config &= ~@as(u32, 1 << 10);
    if (features.contains(.busmastering_dma)) config |= 1 << 2;
    if (features.contains(.memory_space_access)) config |= 1 << 1;
    if (features.contains(.io_port_access)) config |= 1 << 0;
    log.debug("Writing config: 0x{x}", .{config});
    device.write_config(u32, config, 4, .kernel);

    if (device.read_config(u32, 4, .kernel) != config) {
        return false;
    }

    for (device.base_addresses) |*base_address_ptr, i| {
        if (~features.bits & (@as(u64, 1) << @intCast(u3, i)) != 0) continue;
        const base_address = base_address_ptr.*;
        if (base_address & 1 != 0) continue; // BAR is an IO port
        log.debug("Actually setting up base address #{}", .{i});

        if (base_address & 0b1000 == 0) {
            // TODO: not prefetchable
        }

        const is_size_64 = base_address & 0b100 != 0;
        log.debug("is size 64: {}", .{is_size_64});

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

        device.base_physical_addresses[i] = kernel.Physical.Address.new(address);
        device.base_virtual_addresses[i] = device.base_physical_addresses[i].to_higher_half_virtual_address();
        const physical_region = kernel.Physical.Memory.Region.new(device.base_physical_addresses[i], size);
        physical_region.map(&kernel.address_space, device.base_virtual_addresses[i], kernel.Virtual.AddressSpace.Flags.from_flags(&.{ .cache_disable, .read_write }));

        log.debug("Virtual 0x{x}. Physical 0x{x}", .{ device.base_virtual_addresses[i].value, device.base_physical_addresses[i].value });
        device.base_addresses_size[i] = size;
    }

    return true;
}
