const Driver = @This();

const root = @import("root");
const common = @import("../common.zig");
const context = @import("context");

const TODO = common.TODO;
const log = common.log.scoped(.AHCI);
const PhysicalAddress = common.PhysicalAddress;
const VirtualAddressSpace = common.VirtualAddressSpace;

const Drivers = @import("../drivers.zig");

const PCI = Drivers.PCI;
const Disk = Drivers.Disk;
const DMA = Drivers.DMA;

pub var drivers: []Driver = undefined;

pci: *PCI.Device,
abar: *HBAMemory,
drives: [32]Drive,
drive_count: u8,

pub const class_code = 0x01;
pub const subclass_code = 0x06;
pub const Initialization = struct {
    pub const Error = error{
        not_found,
        allocation_failed,
    };

    pub fn callback(virtual_address_space: *VirtualAddressSpace, pci: *PCI) Error![]Driver {
        const found = pci.find_devices(class_code, subclass_code);
        common.runtime_assert(@src(), found.count >= 1);

        if (found.count == 0) return &[_]Driver{};
        log.debug("Found {} AHCI PCI controllers", .{found.count});

        var ahci_drivers = virtual_address_space.heap.allocator.alloc(Driver, found.count) catch return Error.allocation_failed;

        for (ahci_drivers) |*driver, driver_i| {
            const device = found.devices[driver_i];
            try driver.initialize(virtual_address_space, device);
        }

        return ahci_drivers;
    }
};

fn initialize(driver: *Driver, virtual_address_space: *VirtualAddressSpace, pci_device: *PCI.Device) Initialization.Error!void {
    driver.pci = pci_device;
    driver.pci.enable_bar(virtual_address_space, 5) catch @panic("wtf");
    driver.abar = PhysicalAddress.new(driver.pci.bars[5]).access_kernel(*HBAMemory);

    driver.probe_ports();
    common.runtime_assert(@src(), driver.drive_count == 1);
    for (driver.drives[0..driver.drive_count]) |*drive| {
        drive.configure(virtual_address_space);
        Drivers.Driver(Disk, Drive).init(virtual_address_space.heap.allocator, drive) catch common.panic(@src(), "Failed to initialized device", .{});
    }
}

fn probe_ports(driver: *Driver) void {
    var ports_implemented = driver.abar.ports_implemented;
    var i: u6 = 0;
    log.debug("Ports implemented: 0b{b}", .{ports_implemented});
    driver.drive_count = 0;
    while (i < 32) : ({
        i += 1;
        ports_implemented >>= 1;
    }) {
        if (@truncate(u1, ports_implemented) != 0) {
            const hba_port = &driver.abar.ports[i];
            const port_type = hba_port.check_type() catch |err| {
                log.err("Port #{} could not be resolved: {}", .{ i, err });
                continue;
            };
            log.debug("Port #{}: {}", .{ i, port_type });

            if (port_type == .sata or port_type == .satapi) {
                const drive = &driver.drives[driver.drive_count];
                driver.drive_count += 1;
                drive.* = Drive{
                    .disk = Disk{
                        .sector_size = 0x200, // TODO: stop hardcoding this
                        .access = Drive.access,
                        .get_dma_buffer = Drive.get_dma_buffer,
                        .type = .ahci,
                    },
                    .hba_port = hba_port,
                    .port_number = i,
                    .port_type = port_type,
                };
            }
        } else {
            log.err("Port #{} not implemented", .{i});
        }
    }
}

pub const HBAPort = struct {
    command_list_base_low: u32,
    command_list_base_high: u32,
    fis_base_address_low: u32,
    fis_base_address_high: u32,
    interrupt_status: u32,
    interrupt_enable: u32,
    command_status: u32,
    reserved0: u32,
    task_file_data: u32,
    signature: PortSignature,
    sata_status: u32,
    sata_control: u32,
    sata_error: u32,
    sata_active: u32,
    command_issue: u32,
    sata_notification: u32,
    fis_switch_control: u32,
    reserved1: [11]u32,
    vendor: [4]u32,

    const present = 0x3;
    const active = 0x1;

    const PortCheckError = error{
        not_present,
        not_active,
        unrecognized_signature,
    };

    fn check_type(port: *HBAPort) PortCheckError!PortType {
        const sata_status = port.sata_status;
        const interface_power_management = @truncate(u3, sata_status >> 8);
        const device_detection = @truncate(u3, sata_status);

        if (device_detection != present) return PortCheckError.not_present;
        if (interface_power_management != active) return PortCheckError.not_active;

        return switch (port.signature) {
            .atapi => .satapi,
            .ata => .sata,
            .pm => .pm,
            .semb => .semb,
            else => blk: {
                log.err("Unrecognized port signature: 0x{x}", .{@enumToInt(port.signature)});
                break :blk PortCheckError.unrecognized_signature;
            },
        };
    }
};

const PortSignature = enum(u32) {
    atapi = 0xeb140101,
    ata = 0x00000101,
    semb = 0xc33c0101,
    pm = 0x96690101,
    _,
};

pub const HBAMemory = struct {
    host_capability: u32,
    global_host_control: u32,
    interrupt_status: u32,
    ports_implemented: u32,
    version: u32,
    ccc_control: u32,
    ccc_ports: u32,
    enclosure_management_location: u32,
    enclosure_management_control: u32,
    host_capabilities_extended: u32,
    bios_handoff_control_status: u32,
    rsv: [0x74]u8,
    vendor: [0x60]u8,
    ports: [32]HBAPort,
};

pub const PortType = enum(u3) {
    sata = 0,
    semb = 1,
    pm = 2,
    satapi = 3,
};

comptime {
    common.comptime_assert(@bitSizeOf(Disk.Operation) == @bitSizeOf(u1));
    common.comptime_assert(@enumToInt(Disk.Operation.read) == 0);
    common.comptime_assert(@enumToInt(Disk.Operation.write) == 1);
}

pub const Drive = struct {
    disk: Disk,
    hba_port: *volatile HBAPort,
    port_type: PortType,
    port_number: u8,

    const pxcmd_cr = 0x8000;
    const pxcmd_fre = 0x0010;
    const pxcmd_st = 0x0001;
    const pxcmd_fr = 0x4000;

    pub const Initialization = struct {
        pub const Context = *Drive;
        pub const Error = error{
            allocation_failure,
        };

        pub fn callback(allocator: common.Allocator, drive: Context) Error!*Drive {
            _ = allocator;
            return drive;
        }
    };

    fn configure(drive: *Drive, virtual_address_space: *VirtualAddressSpace) void {
        drive.stop_command();
        defer drive.start_command();
        {
            // TODO: maybe don't allocate as much?
            // TODO: batch allocations
            const command_list_alloc_result = virtual_address_space.allocate_extended(context.page_size, null, .{ .write = true }) catch @panic("wtf");
            // TODO: what's 1024?
            common.zero(command_list_alloc_result.virtual_address.access([*]u8)[0..1024]);
            const command_list_base = command_list_alloc_result.physical_address.value;
            drive.hba_port.command_list_base_low = @truncate(u32, command_list_base);
            drive.hba_port.command_list_base_high = @truncate(u32, command_list_base >> 32);

            const fis_alloc_result = virtual_address_space.allocate_extended(context.page_size, null, .{ .write = true }) catch @panic("Wtf");
            common.zero(fis_alloc_result.virtual_address.access([*]u8)[0..256]);
            const fis_base = fis_alloc_result.physical_address.value;
            drive.hba_port.fis_base_address_low = @truncate(u32, fis_base);
            drive.hba_port.fis_base_address_high = @truncate(u32, fis_base >> 32);

            const command_headers = command_list_alloc_result.virtual_address.access([*]volatile HBACommandHeader)[0..32];
            const command_table_address = virtual_address_space.allocate_extended(context.page_size, null, .{ .write = true }) catch @panic("Wtf");
            common.zero(command_table_address.virtual_address.access([*]u8)[0..context.page_size]);
            for (command_headers) |*header, i| {
                header.prdt_length = 8; // TODO: figure out how to get the value
                const address = command_table_address.physical_address.value + (i << 8);
                header.command_table_base_address_low = @truncate(u32, address);
                header.command_table_base_address_high = @truncate(u32, address >> 32);
            }
        }
    }

    const ReadError = error{
        timeout,
        interrupt_status,
    };

    const AtaCommand = enum(u8) {
        read_dma_ex = 0x25,
    };

    const ata_dev_busy = 0x80;
    const ata_dev_drq = 0x08;

    const FISRegisterHardwareToDevice = packed struct {
        fis_type: FISType,
        port_multiplier: u4,
        reserved: u3,
        command_control: bool,

        command: AtaCommand,
        feature_low: u8,

        lba0: u8,
        lba1: u8,
        lba2: u8,

        device_register: u8,
        lba3: u8,
        lba4: u8,
        lba5: u8,
        feature_high: u8,

        count_low: u8,
        count_high: u8,
        iso_command_completion: u8,
        control: u8,

        reserved1: [4]u8,

        comptime {
            common.comptime_assert(@sizeOf(FISRegisterHardwareToDevice) == 5 * @sizeOf(u32));
        }
    };

    const HBAPRDTEntry = packed struct {
        data_base_address_low: u32,
        data_base_address_high: u32,
        reserved: u32,
        byte_count: u22,
        reserved1: u9,
        interrupt_on_completion: bool,

        comptime {
            common.comptime_assert(@sizeOf(HBAPRDTEntry) == @sizeOf(u64) * 2);
        }
    };

    const HBACommandTable = struct {
        command_fis: [64]u8,
        atapi_command: [16]u8,
        reserved: [48]u8,

        fn get_entries(command_table: *volatile HBACommandTable, entry_count: u32) []HBAPRDTEntry {
            return @intToPtr([*]HBAPRDTEntry, @ptrToInt(command_table) + @sizeOf(HBACommandTable))[0..entry_count];
        }

        comptime {
            common.comptime_assert(@sizeOf(HBACommandTable) == @sizeOf(u8) * 128);
        }
    };

    const FISType = enum(u8) {
        reg_h2d = 0x27,
        reg_d2h = 0x34,
        dma_act = 0x39,
        dma_setup = 0x41,
        data = 0x46,
        bist = 0x58,
        pio_setup = 0x5f,
        dev_bits = 0xa1,
    };

    const hba_pxis_tfes = 1 << 30;

    fn access(disk: *Disk, context_ptr: u64, buffer: *DMA.Buffer, disk_work: Disk.Work) u64 {
        common.runtime_assert(@src(), buffer.completed_size == 0);
        common.runtime_assert(@src(), buffer.total_size >= disk_work.sector_count * disk.sector_size);
        const sector_low = @truncate(u32, disk_work.sector_offset);
        const sector_high = @intCast(u16, disk_work.sector_offset >> 32);
        common.runtime_assert(@src(), disk_work.sector_count <= common.max_int(u16));
        const sector_count = @intCast(u16, disk_work.sector_count);

        const drive = @ptrCast(*Drive, disk);
        drive.hba_port.interrupt_status = common.max_int(u32);

        const command_header = PhysicalAddress.new(drive.hba_port.command_list_base_low | (@as(u64, drive.hba_port.command_list_base_high) << 32)).access_higher_half(*volatile HBACommandHeader);
        command_header.command_fis_length = @sizeOf(FISRegisterHardwareToDevice) / @sizeOf(u32);
        command_header.operation = disk_work.operation;
        // TODO: why 1
        command_header.prdt_length = 1;

        const command_table = PhysicalAddress.new(command_header.command_table_base_address_low | (@as(u64, command_header.command_table_base_address_high) << 32)).access_higher_half(*volatile HBACommandTable);
        command_table.* = common.zeroes(HBACommandTable);
        const entries = command_table.get_entries(command_header.prdt_length);
        common.zero_slice(HBAPRDTEntry, entries);

        const virtual_address_space = @intToPtr(*VirtualAddressSpace, context_ptr);
        const buffer_base_physical_address = virtual_address_space.translate_address(buffer.address) orelse @panic("wtF");
        const buffer_physical_address = buffer_base_physical_address.offset(buffer.completed_size);

        // TODO: stop hardcoding this?
        const entry = &entries[0];
        entry.data_base_address_low = @truncate(u32, buffer_physical_address.value);
        entry.data_base_address_high = @truncate(u32, buffer_physical_address.value >> 32);
        entry.byte_count = @intCast(u22, (disk_work.sector_count << 9) - 1);
        entry.interrupt_on_completion = true;

        const command_fis = @ptrCast(*FISRegisterHardwareToDevice, &command_table.command_fis);
        command_fis.fis_type = .reg_h2d;
        command_fis.command_control = true;
        command_fis.command = .read_dma_ex;

        command_fis.lba0 = @truncate(u8, sector_low);
        command_fis.lba1 = @truncate(u8, sector_low >> 8);
        command_fis.lba2 = @truncate(u8, sector_low >> 16);
        command_fis.lba3 = @truncate(u8, sector_low >> 24);
        command_fis.lba4 = @truncate(u8, sector_high);
        command_fis.lba5 = @truncate(u8, sector_high >> 8);

        command_fis.device_register = 1 << 6; // TODO: LBA mode

        command_fis.count_low = @truncate(u8, sector_count);
        command_fis.count_high = @truncate(u8, sector_count >> 8);

        // TODO: improve
        var spin: u64 = 0;

        while (drive.hba_port.task_file_data & (ata_dev_busy | ata_dev_drq) != 0 and spin < 1_000_000) : (spin += 1) {}

        if (spin == 1_000_000) {
            @panic("Spin hit");
        }

        drive.hba_port.command_issue = 1;

        while (true) {
            if (drive.hba_port.command_issue == 0) break;
            if (drive.hba_port.interrupt_status & hba_pxis_tfes != 0) @panic("interrupt status");
        }

        return disk_work.sector_count;
    }

    fn get_dma_buffer(disk: *Disk, allocator: common.Allocator, sector_count: u64) common.Allocator.Error!DMA.Buffer {
        const sector_size = disk.sector_size;
        const byte_size = sector_count * sector_size;
        return DMA.Buffer.new(allocator, .{ .size = common.align_forward(byte_size, context.page_size), .alignment = common.align_forward(sector_size, context.page_size) }) catch @panic("unable to initialize buffer");
    }

    fn start_command(drive: *Drive) void {
        while (drive.hba_port.command_status & pxcmd_cr != 0) {}

        drive.hba_port.command_status |= pxcmd_fre;
        drive.hba_port.command_status |= pxcmd_st;
    }

    fn stop_command(drive: *Drive) void {
        drive.hba_port.command_status &= ~@as(u32, pxcmd_st);
        drive.hba_port.command_status &= ~@as(u32, pxcmd_fre);

        while (true) {
            if (drive.hba_port.command_status & pxcmd_fr == 0) {
                if (drive.hba_port.command_status & pxcmd_cr == 0) {
                    break;
                }
            }
        }
    }
};

const HBACommandHeader = packed struct {
    command_fis_length: u5,
    atapi: bool,
    operation: Disk.Operation,
    prefetchable: bool,

    reset: bool,
    bist: bool,
    clear_busy: bool,
    reserved: bool,
    port_multiplier: u4,

    prdt_length: u16,
    prdb_count: u32,
    command_table_base_address_low: u32,
    command_table_base_address_high: u32,
    reserved1: [4]u32,

    comptime {
        common.comptime_assert(@sizeOf(HBACommandHeader) == 8 * @sizeOf(u32));
    }
};
