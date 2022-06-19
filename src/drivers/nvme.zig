const kernel = @import("../kernel/kernel.zig");
const log = kernel.log.scoped(.NVMe);
const PCIController = @import("pci.zig");
const PCIDevice = @import("pci_device.zig");

const NVMe = @This();
pub var controller: NVMe = undefined;

device: *PCIDevice,

pub fn new(device: *PCIDevice) NVMe {
    return NVMe{
        .device = device,
    };
}

pub fn find(pci: *PCIController) ?*PCIDevice {
    return pci.find_device(0x1, 0x8);
}

const Error = error{
    not_found,
};

pub fn init(pci: *PCIController) Error!void {
    const nvme_device = find(pci) orelse return Error.not_found;
    log.debug("Found NVMe drive", .{});
    controller = NVMe.new(nvme_device);
    const result = controller.device.enable_features(PCIDevice.Features.from_flags(&.{ .interrupts, .busmastering_dma, .memory_space_access, .bar0 }));
    kernel.assert(@src(), result);
    log.debug("Device features enabled", .{});
    unreachable;
}
