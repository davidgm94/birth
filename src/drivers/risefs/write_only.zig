const std = @import("../../common/std.zig");
const log = std.log.scoped(.RiseFS);
const RiseFS = @import("../../common/risefs.zig");
const FilesystemInterface = @import("../filesystem_interface.zig");
const DiskInterface = @import("../disk_interface.zig");
const DMA = @import("../dma.zig");

const Driver = @This();

fs: FilesystemInterface,

pub fn new(disk: *DiskInterface) Driver {
    return Driver{
        .fs = FilesystemInterface.new(.{ .filesystem_type = .rise, .disk = disk, .callback_read_file = null, .callback_write_file = RiseFS.write_file }),
    };
}

pub fn get_signature() []const u8 {
    return &RiseFS.default_signature;
}

pub fn get_superblock_size() u64 {
    return @sizeOf(RiseFS.Superblock);
}
