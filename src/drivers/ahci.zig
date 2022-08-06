const Driver = @This();

const root = @import("root");
const common = @import("../common.zig");

const TODO = common.TODO;
const log = common.log.scoped(.AHCI);
const PhysicalAddress = common.PhysicalAddress;
const VirtualAddressSpace = common.VirtualAddressSpace;

const drivers = @import("../drivers.zig");

const PCI = drivers.PCI;

pci: *PCI.Device,
hba_memory: *HBAMemory,

pub const class_code = 0x01;
pub const subclass_code = 0x06;
pub const Initialization = struct {
    pub const Error = error{
        not_found,
        allocation_failed,
    };

    pub fn callback(virtual_address_space: *VirtualAddressSpace, pci: *PCI) Error!void {
        const found = pci.find_devices(class_code, subclass_code);
        common.runtime_assert(@src(), found.count >= 1);

        if (found.count == 0) return Error.not_found;
        log.debug("Found {} AHCI PCI controllers", .{found.count});

        for (found.devices[0..found.count]) |device| {
            const d = try initialize(virtual_address_space, device);
            _ = d;
        }

        TODO(@src());
        //pci.find_device
    }
};

pub fn initialize(virtual_address_space: *VirtualAddressSpace, pci_device: *PCI.Device) Initialization.Error!*Driver {
    const driver = virtual_address_space.heap.allocator.create(Driver) catch return Initialization.Error.allocation_failed;
    driver.pci = pci_device;
    const hba_physical_address = driver.pci.bars[5];
    _ = hba_physical_address;
    if (true) @panic("here");
    //virtual_address_space.map_physical_region
    //driver.hba_memory = @intToPtr(*HBAMemory, );
    //log.debug("Drive HBA memory: {}", .{driver.hba_memory});

    TODO(@src());
}

pub const HBAPort = struct {
    command_list_base: u32,
    command_list_base_upper: u32,
    fis_base_address: u32,
    fis_base_address_upper: u32,
    interrupt_status: u32,
    interrupt_enable: u32,
    command_status: u32,
    reserved0: u32,
    task_file_data: u32,
    signature: u32,
    sata_status: u32,
    sata_control: u32,
    sata_error: u32,
    sata_active: u32,
    command_issue: u32,
    sata_notification: u32,
    fis_switch_control: u32,
    reserved1: [11]u32,
    vendor: [4]u32,
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
    ports: [1]HBAPort,
};
