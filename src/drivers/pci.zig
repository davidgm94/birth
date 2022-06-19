const kernel = @import("../kernel/kernel.zig");
const log = kernel.log.scoped(.PCI);
const Controller = @This();
const Device = @import("pci_device.zig");

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
