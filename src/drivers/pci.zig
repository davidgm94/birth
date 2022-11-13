const Controller = @This();
// TODO: batch PCI register access

const common = @import("common");
const assert = common.assert;
const log = common.log.scoped(.PCI);
const zeroes = common.zeroes;

const rise = @import("rise");
const DeviceManager = rise.DeviceManager;
const panic = rise.panic;
const PhysicalAddress = rise.PhysicalAddress;
const VirtualAddress = rise.VirtualAddress;
const VirtualAddressSpace = rise.VirtualAddressSpace;

const arch = @import("arch");

const AHCI = @import("ahci.zig");

devices: []Device,

pub var controller: Controller = undefined;

const Error = error{
    no_device_found,
};

pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace) !void {
    try enumerate(device_manager, virtual_address_space);
}

const BusScanState = enum(u8) {
    do_not_scan = 0,
    scan_next = 1,
    scanned = 2,
};

pub const CommonHeader = packed struct {
    vendor_id: u16,
    device_id: u16,
    command: u16,
    status: u16,
    prog_if: u8,
    revision_id: u8,
    subclass_code: u8,
    class_code: u8,
    cache_line_size: u8,
    latency_timer: u8,
    header_type: u8,
    bist: u8,

    comptime {
        assert(@sizeOf(@This()) == 0x10);
    }
};

pub const HeaderType0x00 = packed struct {
    vendor_id: u16,
    device_id: u16,
    command: u16,
    status: u16,
    prog_if: u8,
    revision_id: u8,
    subclass_code: u8,
    class_code: u8,
    cache_line_size: u8,
    latency_timer: u8,
    header_type: u8,
    bist: u8,
    // Start of specific header
    bar0: u32,
    bar1: u32,
    bar2: u32,
    bar3: u32,
    bar4: u32,
    bar5: u32,
    cardbus_cis_pointer: u32,
    subsystem_vendor_id: u16,
    subsystem_id: u16,
    expansion_rom_base_address: u32,
    capabilities_pointer: u8,
    reserved1: u8,
    reserved2: u16,
    reserved3: u32,
    interrupt_line: u8,
    interrupt_pin: u8,
    min_grant: u8,
    max_latency: u8,

    comptime {
        assert(@sizeOf(@This()) == 0x40);
    }
};

fn check_vendor(bus: u8, slot: u8, function: u8) bool {
    const vendor_id = read_field_from_header(CommonHeader, "vendor_id", bus, slot, function);
    return vendor_id != common.max_int(u16);
}

const HeaderType = enum(u8) {
    x0 = 0,
    x1 = 1,
    x2 = 2,
};

const PCIDevices = .{AHCI};

fn enumerate(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace) !void {
    var bus_scan_states = zeroes([256]BusScanState);
    var base_function: u8 = 0;
    const base_header_type = read_field_from_header(CommonHeader, "header_type", 0, 0, base_function);
    assert(base_header_type == 0x0);
    const base_function_count: u8 = if (base_header_type & 0x80 != 0) 8 else 1;
    var buses_to_scan: u8 = 0;

    while (base_function < base_function_count) : (base_function += 1) {
        if (!check_vendor(0, 0, base_function)) continue;
        bus_scan_states[base_function] = .scan_next;
        buses_to_scan += 1;
    }

    const original_bus_to_scan_count = buses_to_scan;

    if (buses_to_scan == 0) panic("unable to find any PCI bus", .{});

    base_function = 0;
    assert(base_function == 0);
    var device_count: u64 = 0;
    // First scan the buses to find out how many PCI devices the computer has
    while (buses_to_scan > 0) {
        var bus_i: u9 = 0;
        while (bus_i < 256) : (bus_i += 1) {
            const bus = @intCast(u8, bus_i);
            if (bus_scan_states[bus] != .scan_next) continue;
            bus_scan_states[bus] = .scanned;
            buses_to_scan -= 1;
            var device: u8 = 0;

            while (device < 32) : (device += 1) {
                if (!check_vendor(bus, device, 0)) continue;

                const header_type = read_field_from_header(CommonHeader, "header_type", bus, device, base_function);
                const function_count: u8 = if (header_type & 0x80 != 0) 8 else 1;
                var function: u8 = 0;

                while (function < function_count) : (function += 1) {
                    if (!check_vendor(bus, device, function)) continue;

                    device_count += 1;
                    const class_code = read_field_from_header(CommonHeader, "class_code", bus, device, function);
                    const subclass_code = read_field_from_header(CommonHeader, "subclass_code", bus, device, function);

                    if (class_code == 0x06 and subclass_code == 0x04) {
                        const secondary_bus = read_field_from_header(HeaderType0x00, "bar1", bus, device, function);
                        buses_to_scan += 1;
                        bus_scan_states[secondary_bus] = .scan_next;
                    }
                }
            }
        }
    }

    base_function = 0;
    while (base_function < base_function_count) : (base_function += 1) {
        if (!check_vendor(0, 0, base_function)) continue;
        bus_scan_states[base_function] = .scan_next;
    }

    if (device_count == 0) {
        return Error.no_device_found;
    }

    buses_to_scan = original_bus_to_scan_count;

    var registered_device_count: u64 = 0;

    base_function = 0;
    assert(base_function == 0);

    while (buses_to_scan > 0) {
        var bus_i: u9 = 0;
        while (bus_i < 256) : (bus_i += 1) {
            const bus = @intCast(u8, bus_i);
            if (bus_scan_states[bus] != .scan_next) continue;

            bus_scan_states[bus] = .scanned;
            buses_to_scan -= 1;

            var device: u8 = 0;

            while (device < 32) : (device += 1) {
                if (!check_vendor(bus, device, base_function)) continue;

                const header_type = read_field_from_header(CommonHeader, "header_type", bus, device, base_function);
                const function_count: u8 = if (header_type & 0x80 != 0) 8 else 1;
                var function: u8 = 0;

                while (function < function_count) : (function += 1) {
                    if (!check_vendor(bus, device, function)) continue;

                    registered_device_count += 1;
                    var pci_device: Device = undefined;

                    pci_device.bus = bus;
                    pci_device.slot = device;
                    pci_device.function = function;

                    pci_device.class_code = pci_device.read_field(CommonHeader, "class_code");
                    pci_device.subclass_code = pci_device.read_field(CommonHeader, "subclass_code");
                    pci_device.prog_if = pci_device.read_field(CommonHeader, "prog_if");

                    pci_device.interrupt_pin = pci_device.read_field(HeaderType0x00, "interrupt_pin");
                    pci_device.interrupt_line = pci_device.read_field(HeaderType0x00, "interrupt_line");

                    pci_device.device_id = pci_device.read_field(CommonHeader, "device_id");
                    pci_device.vendor_id = pci_device.read_field(CommonHeader, "vendor_id");
                    pci_device.subsystem_id = pci_device.read_field(HeaderType0x00, "subsystem_id");
                    pci_device.subsystem_vendor_id = pci_device.read_field(HeaderType0x00, "subsystem_vendor_id");

                    pci_device.bars[0] = pci_device.read_field(HeaderType0x00, "bar0");
                    pci_device.bars[1] = pci_device.read_field(HeaderType0x00, "bar1");
                    pci_device.bars[2] = pci_device.read_field(HeaderType0x00, "bar2");
                    pci_device.bars[3] = pci_device.read_field(HeaderType0x00, "bar3");
                    pci_device.bars[4] = pci_device.read_field(HeaderType0x00, "bar4");
                    pci_device.bars[5] = pci_device.read_field(HeaderType0x00, "bar5");

                    const class_code_name = if (pci_device.class_code < class_code_names.len) class_code_names[pci_device.class_code] else "Unknown";
                    const subclass_code_name = switch (pci_device.class_code) {
                        1 => if (pci_device.subclass_code < subclass1_code_names.len) subclass1_code_names[pci_device.subclass_code] else "",
                        12 => if (pci_device.subclass_code < subclass12_code_names.len) subclass12_code_names[pci_device.subclass_code] else "",
                        else => "",
                    };

                    log.debug("PCI device. Class 0x{x} ({s}). Subclass: 0x{x} ({s}). Prog IF: 0x{x}", .{ pci_device.class_code, class_code_name, pci_device.subclass_code, subclass_code_name, pci_device.prog_if });

                    inline for (PCIDevices) |PCIDevice| {
                        if (PCIDevice.class_code == pci_device.class_code and PCIDevice.subclass_code == pci_device.subclass_code) {
                            try PCIDevice.init(device_manager, virtual_address_space, pci_device);
                            break;
                        }
                    }
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

pub const FindDeviceResult = struct {
    devices: [32]*Device,
    count: u32,
};

pub fn find_devices(driver: *Controller, class_code: u16, subclass_code: u16) FindDeviceResult {
    var result = zeroes(FindDeviceResult);
    for (driver.devices) |*device| {
        if (device.class_code == class_code and device.subclass_code == subclass_code) {
            result.devices[result.count] = device;
            result.count += 1;
        }
    }

    return result;
}

pub const Device = struct {
    device_id: u16,
    vendor_id: u16,
    subsystem_id: u16,
    subsystem_vendor_id: u16,
    domain: u32,
    class_code: u8,
    subclass_code: u8,
    prog_if: u8,
    bus: u8,
    slot: u8,
    function: u8,
    interrupt_pin: u8,
    interrupt_line: u8,
    bars: [6]u32,
    bar_sizes: [6]u32,
    bar_physical_addresses: [6]PhysicalAddress,

    pub inline fn read_config(device: *Device, comptime T: type, offset: u8) T {
        return arch.PCI.read_config(T, device.bus, device.slot, device.function, offset);
    }

    pub inline fn write_config(device: *Device, comptime T: type, value: T, offset: u8) void {
        return arch.PCI.write_config(T, value, device.bus, device.slot, device.function, offset);
    }

    const BarEnableError = error{
        bar_is_an_io_port,
        todo_prefetch,
    };

    pub fn enable_bar(device: *Device, virtual_address_space: *VirtualAddressSpace, comptime bar_i: comptime_int) !VirtualAddress {
        const bar = device.bars[bar_i];

        if (@truncate(u1, bar) != 0) {
            log.err("BAR #{} is an IO port", .{bar});
            return BarEnableError.bar_is_an_io_port;
        }

        if (bar & 0b1000 != 0) {
            log.err("TODO: prefetch", .{});
            return BarEnableError.todo_prefetch;
        }

        const is_size_64 = bar & 0b100 != 0;
        log.debug("Is size 64: {}", .{is_size_64});
        assert(!is_size_64);
        const bar_header_offset = @offsetOf(HeaderType0x00, "bar0") + (@sizeOf(u32) * bar_i);
        device.write_config(u32, common.max_int(u32), bar_header_offset);
        const size1 = device.read_config(u32, bar_header_offset);
        const size2 = size1 | (@as(u64, common.max_int(u32)) << 32);
        assert(size2 != 0);
        device.write_config(u32, bar, bar_header_offset);

        const size3 = size2 & 0xffff_ffff_ffff_fff0;
        const size = @intCast(u32, ~size3 + 1);
        const physical_address = PhysicalAddress.new(bar & 0xffff_fff0);
        log.debug("Enabling BAR #{}. Address: 0x{x}. Size: {}. Proceeding to map it...", .{ bar_i, physical_address.value, size });
        device.bar_physical_addresses[bar_i] = physical_address;
        device.bar_sizes[bar_i] = size;
        const virtual_address = physical_address.to_higher_half_virtual_address();
        const page_count = @divExact(size, arch.page_size);
        _ = page_count;
        virtual_address_space.map_reserved_region(physical_address, virtual_address, size, .{ .write = true, .cache_disable = true });

        return virtual_address;
    }

    pub fn read_field(device: *Device, comptime HT: type, comptime field_name: []const u8) TypeFromFieldName(HT, field_name) {
        const result = read_field_from_header(HT, field_name, device.bus, device.slot, device.function);
        return result;
    }
};

// TODO: Maybe it's required to implement an extended function which accepts a non-harcoded offset of the field?
fn read_field_from_header(comptime HT: type, comptime field_name: []const u8, bus: u8, slot: u8, function: u8) TypeFromFieldName(HT, field_name) {
    const FieldType = TypeFromFieldName(HT, field_name);
    return arch.PCI.read_config(FieldType, bus, slot, function, @offsetOf(HT, field_name));
}

fn TypeFromFieldName(comptime HeaderT: type, comptime field_name: []const u8) type {
    comptime var header: HeaderT = undefined;
    return @TypeOf(@field(header, field_name));
}
