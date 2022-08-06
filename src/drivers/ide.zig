const Driver = @This();

const root = @import("root");
const common = @import("../common.zig");
const drivers = @import("../drivers.zig");
const TODO = common.TODO;
const log = common.log.scoped(.IDE);

const PCI = drivers.PCI;

pub var driver: *Driver = undefined;

config: Config,
channels: [Channel.count]Channel,
identify_data: [sector_size / 2]u16,
devices: [max_device_count]Device,
device_count: u8,

const sector_size = 0x200;
const max_device_count = 4;
const class_code = 0x01;
const subclass_code = 0x01;

const Config = packed struct {
    primary_pci_native_mode: bool,
    primary_can_modify_pci_native_mode: bool,
    secondary_pci_native_mode: bool,
    secondary_can_modify_pci_native_mode: bool,
    padding: u3,
    dma: bool,

    comptime {
        common.comptime_assert(common.is_same_packed_size(Config, u8));
    }
};

pub const Initialization = struct {
    pub const Error = error{
        not_found,
        allocation_failed,
    };

    pub fn callback(virtual_address_space: *common.VirtualAddressSpace, controller: *PCI) Error!*Driver {
        common.runtime_assert(@src(), common.cpu.arch == .x86_64);
        const device = controller.find_device(class_code, subclass_code) orelse return Error.not_found;
        const prog_if_value = device.read_field(PCI.CommonHeader, "prog_if");
        const config = @bitCast(Config, prog_if_value);
        log.debug("Config: {}", .{config});
        common.runtime_assert(@src(), !config.primary_pci_native_mode);
        common.runtime_assert(@src(), !config.primary_can_modify_pci_native_mode);
        common.runtime_assert(@src(), !config.secondary_pci_native_mode);
        common.runtime_assert(@src(), !config.secondary_can_modify_pci_native_mode);
        common.runtime_assert(@src(), !config.dma);

        var ide = virtual_address_space.heap.allocator.create(Driver) catch return Error.allocation_failed;
        ide.* = common.zeroes(Driver);

        initialize(ide, parallel_bars[0], parallel_bars[1], parallel_bars[2], parallel_bars[3], 0);

        TODO(@src());
    }
};

pub const parallel_bars = [_]u32{ 0x1f0, 0x3f6, 0x170, 0x376 };

var identify_data_buffer: [0x200 / 2]u16 align(0x1000) = undefined;

fn initialize(ide: *Driver, bar0: u32, bar1: u32, bar2: u32, bar3: u32, bar4: u32) void {
    ide.channels[@enumToInt(ChannelType.primary)].base = @intCast(u16, (bar0 & 0xffff_fffc) + parallel_bars[0] * @boolToInt(bar0 == 0));
    ide.channels[@enumToInt(ChannelType.primary)].control_base = @intCast(u16, (bar1 & 0xffff_fffc) + parallel_bars[1] * @boolToInt(bar1 == 0));

    ide.channels[@enumToInt(ChannelType.secondary)].base = @intCast(u16, (bar2 & 0xffff_fffc) + parallel_bars[2] * @boolToInt(bar2 == 0));
    ide.channels[@enumToInt(ChannelType.secondary)].control_base = @intCast(u16, (bar3 & 0xffff_fffc) + parallel_bars[3] * @boolToInt(bar3 == 0));

    ide.channels[@enumToInt(ChannelType.primary)].bus_master_ide = @intCast(u16, (bar4 & 0xffff_fffc) + 0);
    ide.channels[@enumToInt(ChannelType.secondary)].bus_master_ide = @intCast(u16, (bar4 & 0xffff_fffc) + 8);

    log.debug("Primary {}\nSecondary {}", .{ ide.channels[0], ide.channels[1] });

    // Disable IRQs
    ide.write(.primary, .control_altstatus, 2);
    ide.write(.secondary, .control_altstatus, 2);

    // Detect ATA-ATAPI devices:
    for (common.enum_values(ChannelType)) |channel| {
        if (ide.read(channel, .command_status) == common.max_int(u8)) {
            log.debug("The bus does not exist", .{});
            continue;
        }

        // Check if the LBA registers are R/W
        ide.write(channel, .lba0, 0xab);
        ide.write(channel, .lba1, 0xcd);
        ide.write(channel, .lba2, 0xef);

        if (ide.read(channel, .lba0) != 0xab) {
            continue;
        }
        if (ide.read(channel, .lba1) != 0xcd) {
            continue;
        }
        if (ide.read(channel, .lba2) != 0xef) {
            continue;
        }

        // Clear the command register
        // TODO: stop hardcoding
        //ide.write(channel, )

        log.debug("Valid bus {s}", .{@tagName(channel)});

        for (common.enum_values(DriveType)) |drive_type| {
            // 1. Select drive
            ide.write(channel, .drive_select, 0xa0 | (@as(u8, @enumToInt(drive_type)) << 4));
            common.arch.x86_64.sleep_on_tsc(1);

            // 2. Send ATA identify command
            ide.write(channel, .lba1, 0);
            ide.write(channel, .lba2, 0);
            ide.write(channel, .command_status, @enumToInt(Command.identify));
            common.arch.x86_64.sleep_on_tsc(1);

            // 3. Polling
            if (ide.read(channel, .command_status) == 0) {
                log.debug("No device found", .{});
                continue;
            }

            log.debug("Device found", .{});

            var is_atapi = false;

            while (true) {
                const status_value = ide.read(channel, .command_status);
                const status = @bitCast(Status, status_value);
                log.debug("Status: {}", .{status});
                if (status.drive_write_fault) @panic("wtf");
                if (status.err) {
                    log.debug("error bit set", .{});
                    const ch_low = ide.read(channel, .lba1);
                    const ch_high = ide.read(channel, .lba2);

                    is_atapi = (ch_low == 0x14 and ch_high == 0xeb) or (ch_low == 0x69 and ch_high == 0x96);
                    log.debug("is atapi: {}", .{is_atapi});
                    if (!is_atapi) {
                        log.debug("Unknown type (maybe it's not a device", .{});
                        continue;
                    }

                    ide.write(channel, .command_status, @enumToInt(Command.identify_packet));
                    common.arch.x86_64.sleep_on_tsc(1);
                    break;
                }

                if (!status.busy and status.data_request_ready) break;
            }

            while (true) {
                const status_value = ide.read(channel, .command_status);
                const status = @bitCast(Status, status_value);
                if (!status.busy) break;
            }

            while (true) {
                const status_value = ide.read(channel, .command_status);
                const status = @bitCast(Status, status_value);
                if (status.err) @panic("error");
                if (status.data_request_ready) break;
            }

            log.debug("Device ready. Is atapi: {}", .{is_atapi});
            common.runtime_assert(@src(), !is_atapi);

            ide.read_identify_data(channel);

            const device = &ide.devices[ide.device_count];
            ide.device_count += 1;

            device.active = true;
            device.ata_type = @intToEnum(ATAType, @boolToInt(is_atapi));
            device.channel = channel;
            device.drive_type = drive_type;
            {
                const signature_ptr = @ptrToInt(&identify_data_buffer) + @enumToInt(IdentifyDataOffsets.device_type);
                log.debug("Signature ptr: 0x{x}", .{signature_ptr});
                device.signature = @intToPtr(*u16, signature_ptr).*;
                const capabilities_ptr = @ptrToInt(&identify_data_buffer) + @enumToInt(IdentifyDataOffsets.capabilities);
                log.debug("Capabilities ptr: 0x{x}", .{capabilities_ptr});
                device.capabilities = @intToPtr(*u16, capabilities_ptr).*;
                const command_sets_ptr = @ptrToInt(&identify_data_buffer) + @enumToInt(IdentifyDataOffsets.command_sets);
                log.debug("Command sets ptr: 0x{x}", .{command_sets_ptr});
                device.command_sets = @intToPtr(*u32, command_sets_ptr).*;

                const model = @ptrCast(*[41]u8, &identify_data_buffer[@enumToInt(IdentifyDataOffsets.model) / 2]);
                log.debug("model: {s}", .{model});
            }
            log.debug("Signature: 0x{x}. Capabilities: 0x{x}. Command sets: 0x{x}", .{ device.signature, device.capabilities, device.command_sets });
            TODO(@src());
        }
    }

    log.debug("Found {} devices", .{ide.device_count});

    TODO(@src());
}

fn read_identify_data(ide: *Driver, channel: ChannelType) void {
    common.runtime_assert(@src(), identify_data_buffer.len == 256);
    const control_base = ide.channels[@enumToInt(channel)].control_base;
    log.debug("Reading from control base: 0x{x}", .{control_base});
    for (identify_data_buffer) |*id| {
        id.* = common.arch.io_read(u16, control_base);
    }
}

fn write(ide: *Driver, channel: ChannelType, register: Register, data: u8) void {
    if (@enumToInt(register) > @enumToInt(Register.command_status) and @enumToInt(register) < @enumToInt(Register.control_altstatus)) {
        log.debug("control register write", .{});
        ide.write(channel, .control_altstatus, 0x80 | ide.channels[@enumToInt(channel)].nIEN);
    }

    if (@enumToInt(register) < @enumToInt(Register.seccount1)) {
        common.arch.x86_64.io_write(u8, ide.channels[@enumToInt(channel)].base + @enumToInt(register) - 0x00, data);
    } else if (@enumToInt(register) < @enumToInt(Register.control_altstatus)) {
        common.arch.x86_64.io_write(u8, ide.channels[@enumToInt(channel)].base + @enumToInt(register) - 0x06, data);
    } else if (@enumToInt(register) <= @enumToInt(Register.devaddress)) {
        common.arch.x86_64.io_write(u8, ide.channels[@enumToInt(channel)].control_base + @enumToInt(register) - 0x0a, data);
    } else if (@enumToInt(register) < 0x16) {
        common.arch.x86_64.io_write(u8, ide.channels[@enumToInt(channel)].bus_master_ide + @enumToInt(register) - 0x0e, data);
    }

    if (@enumToInt(register) > @enumToInt(Register.command_status) and @enumToInt(register) < @enumToInt(Register.control_altstatus)) {
        log.debug("control register write", .{});
        ide.write(channel, .control_altstatus, 0x80 | ide.channels[@enumToInt(channel)].nIEN);
    }
}

fn read(ide: *Driver, channel: ChannelType, register: Register) u8 {
    var result: u8 = 0;

    if (@enumToInt(register) > @enumToInt(Register.command_status) and @enumToInt(register) < @enumToInt(Register.control_altstatus)) {
        log.debug("control register write", .{});
        ide.write(channel, .control_altstatus, 0x80 | ide.channels[@enumToInt(channel)].nIEN);
    }

    if (@enumToInt(register) < @enumToInt(Register.seccount1)) {
        result = common.arch.x86_64.io_read(u8, ide.channels[@enumToInt(channel)].base + @enumToInt(register) - 0x00);
    } else if (@enumToInt(register) < @enumToInt(Register.control_altstatus)) {
        result = common.arch.x86_64.io_read(u8, ide.channels[@enumToInt(channel)].base + @enumToInt(register) - 0x06);
    } else if (@enumToInt(register) <= @enumToInt(Register.devaddress)) {
        result = common.arch.x86_64.io_read(u8, ide.channels[@enumToInt(channel)].control_base + @enumToInt(register) - 0x0a);
    } else if (@enumToInt(register) < 0x16) {
        result = common.arch.x86_64.io_read(u8, ide.channels[@enumToInt(channel)].bus_master_ide + @enumToInt(register) - 0x0e);
    }

    if (@enumToInt(register) > @enumToInt(Register.command_status) and @enumToInt(register) < @enumToInt(Register.control_altstatus)) {
        log.debug("control register write", .{});
        ide.write(channel, .control_altstatus, 0x80 | ide.channels[@enumToInt(channel)].nIEN);
    }

    return result;
}

pub const Register = enum(u8) {
    data = 0x0,
    error_features = 0x1,
    seccount0 = 0x2,
    lba0 = 0x3,
    lba1 = 0x4,
    lba2 = 0x5,
    drive_select = 0x6,
    command_status = 0x7,
    seccount1 = 0x8,
    lba3 = 0x9,
    lba4 = 0xa,
    lba5 = 0xb,
    control_altstatus = 0xc,
    devaddress = 0xd,
    _,
};

pub const Status = packed struct {
    err: bool,
    index: bool,
    corrected_data: bool,
    data_request_ready: bool,
    drive_seek_complete: bool,
    drive_write_fault: bool,
    drive_ready: bool,
    busy: bool,

    comptime {
        common.comptime_assert(common.is_same_packed_size(Status, u8));
    }
};

pub const MostRecentError = packed struct {
    no_address_mask: bool,
    track_0_not_found: bool,
    command_aborted: bool,
    media_change_request: bool,
    id_mark_not_found: bool,
    media_changed: bool,
    uncorrectable_data: bool,
    bad_block: bool,

    comptime {
        common.comptime_assert(common.is_same_packed_size(MostRecentError, u8));
    }
};

pub const Command = enum(u8) {
    read_pio = 0x20,
    read_pio_ext = 0x24,
    read_dma = 0xc8,
    read_dma_ext = 0x25,
    write_pio = 0x30,
    write_pio_ext = 0x34,
    write_dma = 0xca,
    write_dma_ext = 0x35,
    cache_flush = 0xe7,
    cache_flush_ext = 0xea,
    packet = 0xa0,
    identify_packet = 0xa1,
    identify = 0xec,
};

pub const ChannelType = enum(u1) {
    primary = 0,
    secondary = 1,
};

pub const Direction = enum(u1) {
    read = 0,
    write = 1,
};

pub const Channel = struct {
    base: u16,
    control_base: u16,
    bus_master_ide: u16,
    nIEN: u8,

    pub const count = common.enum_values(ChannelType).len;
};

pub const ATAType = enum(u1) {
    ata = 0,
    atapi = 1,
};

pub const DriveType = enum(u1) {
    master = 0,
    slave = 1,
};

pub const Device = struct {
    active: bool,
    channel: ChannelType,
    drive_type: DriveType,
    ata_type: ATAType,
    signature: u16,
    capabilities: u16,
    command_sets: u32,
    size: u32,
    mode: [41]u8,
};

const IdentifyDataOffsets = enum(u8) {
    device_type = 0,
    cylinders = 2,
    heads = 6,
    sectors = 12,
    serial = 20,
    model = 54,
    capabilities = 98,
    field_valid = 106,
    max_lba = 120,
    command_sets = 164,
    max_lba_ext = 200,
};
