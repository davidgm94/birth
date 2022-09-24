const std = @import("../../../common/std.zig");

const AHCI = @import("../../../drivers/ahci.zig");
const ACPI = @import("../../../drivers/acpi.zig");
const DeviceManager = @import("../../device_manager.zig");
const Driver = @import("../../../drivers/common.zig");
const Disk = @import("../../../drivers/disk.zig");
const Filesystem = @import("../../../drivers/filesystem.zig");
const Graphics = @import("../../../drivers/graphics.zig");
const kernel = @import("../../kernel.zig");
const LimineGraphics = @import("../../../drivers/limine_graphics.zig");
const PCI = @import("../../../drivers/pci.zig");
const PhysicalAddress = @import("../../physical_address.zig");
const RNUFS = @import("../../../drivers/rnufs/rnufs.zig");
const x86_64 = @import("common.zig");
const VirtualAddressSpace = @import("../../virtual_address_space.zig");

const log = std.log.scoped(.Drivers);

pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace) !void {
    try ACPI.init(device_manager, virtual_address_space);
    try PCI.init(device_manager, virtual_address_space);
    try LimineGraphics.init(@import("root").bootloader_framebuffer.response.?.framebuffers.?.*[0]);
}
