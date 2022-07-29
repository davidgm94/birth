const common = @import("../../common.zig");
const Virtio = @import("../virtio.zig");
const PCI = @import("../pci.zig");

const Driver = @This();

const TODO = common.TODO;

pub var driver: *Driver = undefined;

pub fn from_pci(controller: *PCI) !*Driver {
    const device = controller.find(@enumToInt(Virtio.TransitionalPCIDeviceID.block_device), Virtio.PCI_vendor_id) orelse @panic("wtf");
    from_pci_device(device);
    TODO(@src());
}

pub fn from_pci_device(device: *PCI.Device) void {
    common.runtime_assert(@src(), device.vendor_id == Virtio.PCI_vendor_id);
    // TODO: there is another way to compute the device id
    common.runtime_assert(@src(), device.device_id == @enumToInt(Virtio.TransitionalPCIDeviceID.block_device));
    Virtio.detect_bars(device);
    TODO(@src());
}
