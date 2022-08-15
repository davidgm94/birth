const std = @import("../../common/std.zig");
const log = std.log.scoped(.RNUFS);
const RNUFS = @import("../../common/rnufs.zig");
const FilesystemInterface = @import("../filesystem_interface.zig");
const DiskInterface = @import("../disk_interface.zig");
const DMA = @import("../dma.zig");

const Allocator = std.Allocator;

const Driver = @This();

fs: FilesystemInterface,

pub fn new(disk: *DiskInterface) Driver {
    return Driver{
        .fs = FilesystemInterface.new(.{ .filesystem_type = .RNU, .disk = disk, .read_file_callback = null, .write_file_callback = RNUFS.write_new_file }),
    };
}

pub fn get_signature() []const u8 {
    return &RNUFS.default_signature;
}

pub fn get_superblock_size() u64 {
    return @sizeOf(RNUFS.Superblock);
}
