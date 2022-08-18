const std = @import("../../../common/std.zig");

const AHCI = @import("../../../drivers/ahci.zig");
const ACPI = @import("../../../drivers/acpi.zig");
const DeviceManager = @import("../../device_manager.zig");
const Driver = @import("../../../drivers/common.zig");
const Disk = @import("../../../drivers/disk.zig");
const Filesystem = @import("../../../drivers/filesystem.zig");
const Graphics = @import("../../../drivers/graphics.zig");
const kernel = @import("../../kernel.zig");
const PCI = @import("../../../drivers/pci.zig");
const PhysicalAddress = @import("../../physical_address.zig");
const RNUFS = @import("../../../drivers/rnufs/rnufs.zig");
const x86_64 = @import("common.zig");
const VirtualAddressSpace = @import("../../virtual_address_space.zig");

const log = std.log.scoped(.Drivers);

pub fn init(device_manager: *DeviceManager, virtual_address_space: *VirtualAddressSpace) !void {
    try driver_tree[0].type.init(device_manager, virtual_address_space, driver_tree[0].children);
    try driver_tree[1].type.init(device_manager, virtual_address_space, driver_tree[1].children);
    try Graphics.init(device_manager, virtual_address_space, &.{kernel.bootloader_framebuffer}, driver_tree[2].children);
}

pub const driver_tree = [_]Driver.Tree{
    .{
        .type = ACPI,
        .children = null,
    },
    .{
        .type = PCI,
        .children = &.{
            .{
                .type = AHCI,
                .children = &.{
                    .{
                        .type = Disk,
                        .children = &.{
                            .{
                                .type = RNUFS,
                                .children = &.{
                                    .{
                                        .type = Filesystem,
                                        .children = null,
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
    .{
        .type = Graphics,
        .children = null,
    },
};
