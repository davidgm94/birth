const common = @import("../common.zig");

const log = common.log.scoped(.Virtio);
const TODO = common.TODO;
const PCI = @import("pci.zig");
pub const Block = @import("virtio/block.zig");

pub const PCI_vendor_id = 0x1af4;

pub const TransitionalPCIDeviceID = enum(u16) {
    network_card = 0x1000,
    block_device = 0x1001,
    memory_ballooning = 0x1002,
    console = 0x1003,
    SCSI_host = 0x1004,
    entropy_source = 0x1005,
    transport_9p = 0x1009,
};

pub fn detect_bars(device: *PCI.Device) void {
    const header_type = device.read_config(u8, PCI.CommonHeader.get_offset("header_type"));
    common.runtime_assert(@src(), header_type == 0);
    const capabilities_pointer = device.read_config(u8, PCI.HeaderType0x00.get_offset("capabilities_pointer")) & 0xfc;
    log.debug("CP: {}", .{capabilities_pointer});
    TODO(@src());
}
