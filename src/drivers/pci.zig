const kernel = @import("../kernel/kernel.zig");
const log = kernel.log.scoped(.PCI);
const TODO = kernel.TODO;
const Controller = @This();
const PrivilegeLevel = kernel.PrivilegeLevel;
const x86_64 = @import("../kernel/arch/x86_64.zig");

devices: []Device,
bus_scan_states: [256]BusScanState,

pub var controller: Controller = undefined;

pub fn init() void {
    controller.enumerate();
}

const BusScanState = enum(u8) {
    do_not_scan = 0,
    scan_next = 1,
    scanned = 2,
};

const pci_read_config = kernel.arch.pci_read_config;
const pci_write_config = kernel.arch.pci_read_config;

fn enumerate(pci: *Controller) void {
    const base_header_type = pci_read_config(u32, 0, 0, 0, 0x0c);
    log.debug("Base header type: 0x{x}", .{base_header_type});
    const base_bus_count: u8 = if (base_header_type & 0x80 != 0) 8 else 1;
    var base_bus: u8 = 0;
    var buses_to_scan: u8 = 0;
    while (base_bus < base_bus_count) : (base_bus += 1) {
        // TODO: ERROR maybe? shouldn't base bus be another parameter?
        const device_id = pci_read_config(u32, 0, 0, base_bus, 0x00);
        if (@truncate(u16, device_id) == 0xffff) continue;
        pci.bus_scan_states[base_bus] = .scan_next;
        buses_to_scan += 1;
    }

    const original_bus_to_scan_count = buses_to_scan;

    if (buses_to_scan == 0) kernel.panic("unable to find any PCI bus", .{});

    var device_count: u64 = 0;
    // First scan the buses to find out how many PCI devices the computer has
    while (buses_to_scan > 0) {
        var bus_i: u9 = 0;
        while (bus_i < 256) : (bus_i += 1) {
            const bus = @intCast(u8, bus_i);
            if (pci.bus_scan_states[bus] != .scan_next) continue;
            log.debug("Scanning bus {}...", .{bus});
            pci.bus_scan_states[bus] = .scanned;
            buses_to_scan -= 1;
            var device: u8 = 0;
            while (device < 32) : (device += 1) {
                const outer_device_id = pci_read_config(u32, bus, device, 0, 0);
                if (@truncate(u16, outer_device_id) == 0xffff) continue;
                log.debug("Outer device id: 0x{x}", .{outer_device_id});

                const header_type = @truncate(u8, pci_read_config(u32, bus, device, 0, 0x0c) >> 16);
                const function_count: u8 = if (header_type & 0x80 != 0) 8 else 1;
                var function: u8 = 0;
                log.debug("Function count: {}", .{function_count});

                while (function < function_count) : (function += 1) {
                    const inner_device_id = pci_read_config(u32, bus, device, function, 0x00);
                    if (@truncate(u16, inner_device_id) == 0xffff) continue;
                    device_count += 1;
                    const device_class = pci_read_config(u32, bus, device, function, 0x08);
                    const class_code = @truncate(u8, device_class >> 24);
                    const subclass_code = @truncate(u8, device_class >> 16);

                    if (class_code == 0x06 and subclass_code == 0x04) {
                        const secondary_bus = @truncate(u8, pci_read_config(u32, bus, device, function, 0x18) >> 8);
                        buses_to_scan += 1;
                        pci.bus_scan_states[secondary_bus] = .scan_next;
                    }
                }
            }
        }
    }

    base_bus = 0;
    while (base_bus < base_bus_count) : (base_bus += 1) {
        // TODO: ERROR maybe? shouldn't base bus be another parameter?
        const device_id = pci_read_config(u32, 0, 0, base_bus, 0x00);
        if (@truncate(u16, device_id) == 0xffff) continue;
        pci.bus_scan_states[base_bus] = .scan_next;
    }

    log.debug("Device count: {}", .{device_count});

    buses_to_scan = original_bus_to_scan_count;
    pci.devices = kernel.core_heap.allocate_many(Device, device_count) orelse @panic("unable to allocate pci devices");

    var registered_device_count: u64 = 0;

    log.debug("Buses to scan: {}", .{buses_to_scan});

    while (buses_to_scan > 0) {
        var bus_i: u9 = 0;
        while (bus_i < 256) : (bus_i += 1) {
            const bus = @intCast(u8, bus_i);
            if (pci.bus_scan_states[bus] != .scan_next) continue;

            log.debug("Scanning bus {}...", .{bus});
            pci.bus_scan_states[bus] = .scanned;
            buses_to_scan -= 1;

            var device: u8 = 0;

            while (device < 32) : (device += 1) {
                const outer_device_id = pci_read_config(u32, bus, device, 0, 0);
                if (@truncate(u16, outer_device_id) == 0xffff) continue;
                log.debug("Outer device id: 0x{x}", .{outer_device_id});

                const header_type = @truncate(u8, pci_read_config(u32, bus, device, 0, 0x0c) >> 16);
                const function_count: u8 = if (header_type & 0x80 != 0) 8 else 1;
                var function: u8 = 0;
                log.debug("Function count: {}", .{function_count});

                while (function < function_count) : (function += 1) {
                    const inner_device_id = pci_read_config(u32, bus, device, function, 0x00);
                    if (@truncate(u16, inner_device_id) == 0xffff) continue;
                    log.debug("Inner Device id: 0x{x}", .{inner_device_id});

                    const device_class = pci_read_config(u32, bus, device, function, 0x08);
                    log.debug("Device class: 0x{x}", .{device_class});
                    const interrupt_information = pci_read_config(u32, bus, device, function, 0x3c);
                    log.debug("Interrupt information: 0x{x}", .{interrupt_information});

                    const pci_device = &pci.devices[registered_device_count];
                    registered_device_count += 1;

                    pci_device.class_code = @truncate(u8, device_class >> 24);
                    pci_device.subclass_code = @truncate(u8, device_class >> 16);
                    pci_device.prog_if = @truncate(u8, device_class >> 8);

                    pci_device.bus = bus;
                    pci_device.slot = device;
                    pci_device.function = function;

                    pci_device.interrupt_pin = @truncate(u8, interrupt_information >> 8);
                    pci_device.interrupt_line = @truncate(u8, interrupt_information);

                    const new_device_id = pci_read_config(u32, bus, device, function, 0x00);
                    kernel.assert(@src(), new_device_id == inner_device_id);
                    pci_device.device_id = new_device_id;
                    pci_device.subsystem_id = pci_read_config(u32, bus, device, function, 0x2c);

                    for (pci_device.base_addresses) |*base_address, i| {
                        base_address.* = pci_device.read_config(u32, 0x10 + 4 * @intCast(u8, i), .kernel);
                    }

                    const class_code_name = if (pci_device.class_code < class_code_names.len) class_code_names[pci_device.class_code] else "Unknown";
                    const subclass_code_name = switch (pci_device.class_code) {
                        1 => if (pci_device.subclass_code < subclass1_code_names.len) subclass1_code_names[pci_device.subclass_code] else "",
                        12 => if (pci_device.subclass_code < subclass12_code_names.len) subclass12_code_names[pci_device.subclass_code] else "",
                        else => "",
                    };
                    const prog_if_name = if (pci_device.class_code == 12 and pci_device.subclass_code == 3 and pci_device.prog_if / 0x10 < prog_if_12_3_names.len) prog_if_12_3_names[pci_device.prog_if / 0x10] else "";
                    log.debug("PCI device. Class 0x{x} ({s}). Subclass: 0x{x} ({s}). Prog IF: {s}", .{ pci_device.class_code, class_code_name, pci_device.subclass_code, subclass_code_name, prog_if_name });
                }
            }
        }
    }
}

pub fn find_device(pci: *Controller, class_code: u8, subclass_code: u8) ?*Device {
    for (pci.devices) |*device| {
        if (device.class_code == class_code and device.subclass_code == subclass_code) {
            return device;
        }
    }

    return null;
}

const class_code_names = [_][]const u8{
    "Unknown",
    "Mass storage controller",
    "Network controller",
    "Display controller",
    "Multimedia controller",
    "Memory controller",
    "Bridge controller",
    "Simple communication controller",
    "Base system peripheral",
    "Input device controller",
    "Docking station",
    "Processor",
    "Serial bus controller",
    "Wireless controller",
    "Intelligent controller",
    "Satellite communication controller",
    "Encryption controller",
    "Signal processing controller",
};

const subclass1_code_names = [_][]const u8{
    "SCSI bus controller",
    "IDE controller",
    "Floppy disk controller",
    "IPI bus controller",
    "RAID controller",
    "ATA controller",
    "Serial ATA",
    "Serial attached SCSI",
    "Non-volatile memory controller (NVMe)",
};

const subclass12_code_names = [_][]const u8{
    "FireWire (IEEE 1394) controller",
    "ACCESS bus",
    "SSA",
    "USB controller",
    "Fibre channel",
    "SMBus",
    "InfiniBand",
    "IPMI interface",
    "SERCOS interface (IEC 61491)",
    "CANbus",
};

const prog_if_12_3_names = [_][]const u8{
    "UHCI",
    "OHCI",
    "EHCI",
    "XHCI",
};

pub const Device = struct {
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
                device.write_bar(u32, index, offset, @truncate(u32, value));
                device.write_bar(u32, index, offset + @sizeOf(u32), @truncate(u32, value >> 32));
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

    pub fn enable_single_interrupt(device: *Device, handler: x86_64.interrupts.HandlerInfo) bool {
        if (device.enable_MSI(handler)) return true;
        if (device.interrupt_pin == 0) return false;
        if (device.interrupt_pin > 4) return false;

        const result = device.enable_features(Features.from_flag(.interrupts));
        kernel.assert(@src(), result);

        // TODO: consider some stuff Essence does?

        TODO(@src());
    }

    pub fn enable_MSI(device: *Device, handler: x86_64.interrupts.HandlerInfo) bool {
        _ = handler;
        const status = device.read_config(u32, 0x04, .kernel) >> 16;

        if (~status & (1 << 4) != 0) return false;

        var pointer = device.read_config(u8, 0x34, .kernel);
        var index: u64 = 0;

        while (true) {
            if (pointer == 0) break;
            if (index >= 0xff) break;
            index += 1;

            const dw = device.read_config(u32, pointer, .kernel);
            const next_pointer = @truncate(u8, dw >> 8);
            const id = @truncate(u8, dw);

            if (id != 5) {
                pointer = next_pointer;
                continue;
            }

            // TODO: maybe this is a bug.NVMe should support MSI
            TODO(@src());
            //const msi =
        }

        return false;
    }
};
