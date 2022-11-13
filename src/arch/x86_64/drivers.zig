// TODO: reorganize
const rise = @import("rise");
const DeviceManager = rise.DeviceManager;
const VirtualAddressSpace = rise.VirtualAddressSpace;

const ACPI = @import("../../../drivers/acpi.zig");
const LimineGraphics = @import("../../../drivers/limine_graphics.zig");
const PCI = @import("../../../drivers/pci.zig");

pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace) !void {
    try ACPI.init(device_manager, virtual_address_space);
    try PCI.init(device_manager, virtual_address_space);
    try LimineGraphics.init(@import("root").bootloader_framebuffer.response.?.framebuffers.?.*[0]);
}
