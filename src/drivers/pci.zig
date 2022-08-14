const Controller = @This();
// TODO: batch PCI register access

const std = @import("../common/std.zig");

const Bitflag = @import("../common/bitflag.zig").Bitflag;
const crash = @import("../kernel/crash.zig");
const DeviceManager = @import("../kernel/device_manager.zig");
const PhysicalAddress = @import("../kernel/physical_address.zig");
const PhysicalMemoryRegion = @import("../kernel/physical_memory_region.zig");
const VirtualAddress = @import("../kernel/virtual_address.zig");
const VirtualAddressSpace = @import("../kernel/virtual_address_space.zig");
const PCI = @import("../kernel/arch/pci.zig");
const io = @import("../kernel/arch/io.zig");

const log = std.log.scoped(.PCI);
const TODO = crash.TODO;
const panic = crash.panic;

devices: []Device,

pub var controller: Controller = undefined;

const Error = error{
    no_device_found,
};
pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace, comptime child_drivers: []const type) !void {
    try enumerate(device_manager, virtual_address_space, child_drivers);
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
        std.assert(@sizeOf(@This()) == 0x10);
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
        std.assert(@sizeOf(@This()) == 0x40);
    }
};

fn check_vendor(bus: u8, slot: u8, function: u8) bool {
    const vendor_id = read_field_from_header(CommonHeader, "vendor_id", bus, slot, function);
    return vendor_id != std.max_int(u16);
}

const HeaderType = enum(u8) {
    x0 = 0,
    x1 = 1,
    x2 = 2,
};

fn enumerate(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace, comptime child_drivers: []const type) !void {
    _ = device_manager;
    _ = virtual_address_space;
    var bus_scan_states = std.zeroes([256]BusScanState);
    var base_function: u8 = 0;
    const base_header_type = read_field_from_header(CommonHeader, "header_type", 0, 0, base_function);
    std.assert(base_header_type == 0x0);
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
    std.assert(base_function == 0);
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
    std.assert(base_function == 0);

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

                    inline for (child_drivers) |Driver| {
                        if (Driver.class_code == pci_device.class_code and Driver.subclass_code == pci_device.subclass_code) {
                            try Driver.init(device_manager, virtual_address_space, pci_device);
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
    var result = std.zeroes(FindDeviceResult);
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
        return PCI.read_config(T, device.bus, device.slot, device.function, offset);
    }

    pub inline fn write_config(device: *Device, comptime T: type, value: T, offset: u8) void {
        return PCI.write_config(T, value, device.bus, device.slot, device.function, offset);
    }

    //pub inline fn read_bar(device: *Device, comptime T: type, index: u64, offset: u64) T {
    //const IntType = std.IntType(.unsigned, @bitSizeOf(T));
    //comptime {
    //std.assert(@sizeOf(T) >= @sizeOf(u32));
    //std.assert(@sizeOf(T) <= @sizeOf(u64));
    //}

    //const base_address = device.base_addresses[index];
    //const mmio_base_address = device.base_virtual_addresses[index];
    //const mmio_address = mmio_base_address.offset(offset);
    //log.debug("MMIO base address: 0x{x}. MMIO address: 0x{x}. Index: {}. Offset: {}. Type: {}", .{ mmio_base_address.value, mmio_address.value, index, offset, T });
    //const do_mmio = base_address & 1 == 0;
    //if (do_mmio) {
    //// Info: @ZigBug. After a read, the value must be bitcasted and assigned of a new variable of the same type in order to work.
    //// If you don't do this, the Zig compiler splits the reads, emitting two or more operations and stopping us to get a good PCI interaction
    //const mmio_ptr = mmio_address.access(*volatile IntType);
    //const mmio_read_value = mmio_ptr.*;
    //const mmio_result: T = @bitCast(T, mmio_read_value);
    //return mmio_result;
    //} else {
    //if (T != u64) {
    //const port = @intCast(u16, (base_address & ~@as(u32, 3)) + offset);
    //return io.read(T, port);
    //} else {
    //return device.read_bar(u32, index, offset) | (@intCast(u64, device.read_bar(u64, index, offset + @sizeOf(u32))) << 32);
    //}
    //}
    //}

    //pub fn write_bar(device: *Device, comptime T: type, index: u64, offset: u64, value: T) void {
    //const IntType = std.IntType(.unsigned, @bitSizeOf(T));
    //comptime {
    //std.assert(@sizeOf(T) >= @sizeOf(u32));
    //std.assert(@sizeOf(T) <= @sizeOf(u64));
    //}
    //const base_address = device.base_addresses[index];
    //const do_mmio = base_address & 1 == 0;
    //const mmio_address = device.base_virtual_addresses[index].offset(offset);
    //if (do_mmio) {
    //// Info: @ZigBug. The value must be bitcasted and assigned of a new variable of the same type and the write it to the MMIO register
    //// in order to work. If you don't do this, the Zig compiler splits the writes, emitting two or more operations and stopping us to get a good PCI interaction
    //const int_value: IntType = @bitCast(IntType, value);
    //mmio_address.access(*align(@alignOf(IntType)) volatile IntType).* = int_value;
    //} else {
    //if (T != u64) {
    //const port = @intCast(u16, (base_address & ~@as(@TypeOf(base_address), 3)) + offset);
    //io.write(T, port, value);
    //} else {
    //device.write_bar(u32, index, offset, @truncate(u32, value));
    //device.write_bar(u32, index, offset + @sizeOf(u32), @truncate(u32, value >> 32));
    //}
    //}
    //}

    //pub const Features = Bitflag(false, u64, enum(u6) {
    //bar0 = 0,
    //bar1 = 1,
    //bar2 = 2,
    //bar3 = 3,
    //bar4 = 4,
    //bar5 = 5,
    //interrupts = 8,
    //busmastering_dma = 9,
    //memory_space_access = 10,
    //io_port_access = 11,
    //});

    //pub fn enable_features(device: *Device, features: Features, virtual_address_space: *VirtualAddressSpace) bool {
    //log.debug("Enabling features for device {}", .{device});
    //var config = device.read_config(u32, 4);
    //if (features.contains(.interrupts)) config &= ~@as(u32, 1 << 10);
    //if (features.contains(.busmastering_dma)) config |= 1 << 2;
    //if (features.contains(.memory_space_access)) config |= 1 << 1;
    //if (features.contains(.io_port_access)) config |= 1 << 0;
    //log.debug("Writing config: 0x{x}", .{config});
    //device.write_config(u32, config, 4);

    //if (device.read_config(u32, 4) != config) {
    //return false;
    //}

    //for (device.base_addresses) |*base_address_ptr, i| {
    //if (~features.bits & (@as(u64, 1) << @intCast(u3, i)) != 0) continue;
    //const base_address = base_address_ptr.*;
    //if (base_address & 1 != 0) continue; // BAR is an IO port
    //log.debug("Actually setting up base address #{}", .{i});

    //if (base_address & 0b1000 == 0) {
    //// TODO: not prefetchable
    //}

    //const is_size_64 = base_address & 0b100 != 0;

    //var address: u64 = 0;
    //var size: u64 = 0;

    //if (is_size_64) {
    //device.write_config(u32, std.max_int(u32), 0x10 + 4 * @intCast(u8, i));
    //device.write_config(u32, std.max_int(u32), 0x10 + 4 * @intCast(u8, i + 1));
    //size = device.read_config(u32, 0x10 + 4 * @intCast(u8, i));
    //size |= @intCast(u64, device.read_config(u32, 0x10 + 4 * @intCast(u8, i + 1))) << 32;
    //device.write_config(u32, base_address, 0x10 + 4 * @intCast(u8, i));
    //device.write_config(u32, device.base_addresses[i + 1], 0x10 + 4 * @intCast(u8, i + 1));
    //address = base_address;
    //address |= @intCast(u64, device.base_addresses[i + 1]) << 32;
    //} else {
    //device.write_config(u32, std.max_int(u32), 0x10 + 4 * @intCast(u8, i));
    //size = device.read_config(u32, 0x10 + 4 * @intCast(u8, i));
    //size |= @as(u64, std.max_int(u32)) << 32;
    //device.write_config(u32, base_address, 0x10 + 4 * @intCast(u8, i));
    //address = base_address;
    //}

    //if (size == 0 or address == 0) return false;
    //size &= ~@as(u64, 0xf);
    //size = ~size + 1;
    //address &= ~@as(u64, 0xf);
    //log.debug("Address: 0x{x}. Size: {}", .{ address, size });

    //device.base_physical_addresses[i] = PhysicalAddress.new(address);
    //device.base_virtual_addresses[i] = device.base_physical_addresses[i].to_higher_half_virtual_address();
    //const physical_region = PhysicalMemoryRegion.new(device.base_physical_addresses[i], size);
    //virtual_address_space.map_physical_region(physical_region, device.base_virtual_addresses[i], .{ .write = true, .cache_disable = true });

    //log.debug("Virtual 0x{x}. Physical 0x{x}", .{ device.base_virtual_addresses[i].value, device.base_physical_addresses[i].value });
    //device.base_addresses_size[i] = size;
    //}

    //return true;
    //}

    const BarEnableError = error{
        bar_is_an_io_port,
        todo_prefetch,
    };

    pub fn enable_bar(device: *Device, virtual_address_space: *VirtualAddressSpace, comptime bar_i: comptime_int) BarEnableError!void {
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
        std.assert(!is_size_64);
        const bar_header_offset = @offsetOf(HeaderType0x00, "bar0") + (@sizeOf(u32) * bar_i);
        device.write_config(u32, std.max_int(u32), bar_header_offset);
        const size1 = device.read_config(u32, bar_header_offset);
        const size2 = size1 | (@as(u64, std.max_int(u32)) << 32);
        std.assert(size2 != 0);
        device.write_config(u32, bar, bar_header_offset);

        const size3 = size2 & 0xffff_ffff_ffff_fff0;
        const size = @intCast(u32, ~size3 + 1);
        const physical_address = PhysicalAddress.new(bar & 0xffff_fff0);
        log.debug("Enabling BAR #{}. Address: 0x{x}. Size: {}. Proceeding to map it...", .{ bar_i, physical_address.value, size });
        device.bar_physical_addresses[bar_i] = physical_address;
        device.bar_sizes[bar_i] = size;
        const virtual_address = physical_address.to_higher_half_virtual_address();
        const physical_memory_region = PhysicalMemoryRegion.new(physical_address, size);
        virtual_address_space.map_physical_region(physical_memory_region, virtual_address, .{ .write = true, .cache_disable = true });
    }

    pub fn read_field(device: *Device, comptime HT: type, comptime field_name: []const u8) TypeFromFieldName(HT, field_name) {
        const result = read_field_from_header(HT, field_name, device.bus, device.slot, device.function);
        return result;
    }
};

// TODO: Maybe it's required to implement an extended function which accepts a non-harcoded offset of the field?
fn read_field_from_header(comptime HT: type, comptime field_name: []const u8, bus: u8, slot: u8, function: u8) TypeFromFieldName(HT, field_name) {
    const FieldType = TypeFromFieldName(HT, field_name);
    return PCI.read_config(FieldType, bus, slot, function, @offsetOf(HT, field_name));
}

fn TypeFromFieldName(comptime HeaderT: type, comptime field_name: []const u8) type {
    comptime var header: HeaderT = undefined;
    return @TypeOf(@field(header, field_name));
}
