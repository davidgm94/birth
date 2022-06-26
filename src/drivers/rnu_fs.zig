const kernel = @import("../kernel.zig");
const log = kernel.log.scoped(.RNUFS);
const Filesystem = @import("filesystem.zig");
const RNUFS = @import("../common/fs.zig");
const GenericDriver = kernel.driver;

const Driver = @This();

fs: Filesystem,

pub const Initialization = struct {
    pub const Context = *kernel.Disk;
    pub const Error = error{
        allocation_failure,
    };
    pub fn callback(allocate: GenericDriver.AllocationCallback, initialization_context: Context) Filesystem.InitializationError!*Driver {
        const driver_allocation = allocate(@sizeOf(Driver)) orelse return Error.allocation_failure;
        const driver = @intToPtr(*Driver, driver_allocation);
        driver.fs.disk = initialization_context;
        driver.fs.read_file_callback = read_file;

        return driver;
    }
};

pub fn seek_file(fs_driver: *Filesystem, name: []const u8) ?SeekResult {
    const sectors_to_read_at_time = 1;
    var sector: u64 = 0;
    var search_buffer: [kernel.arch.sector_size]u8 = undefined;

    while (true) {
        log.debug("FS driver asking read", .{});
        const sectors_read = fs_driver.disk.read_callback(fs_driver.disk, &search_buffer, sector, sectors_to_read_at_time);
        log.debug("FS driver ending read", .{});
        if (sectors_read != sectors_to_read_at_time) @panic("driver failure");
        var node = @ptrCast(*RNUFS.Node, @alignCast(@alignOf(RNUFS.Node), &search_buffer));
        const node_name_cstr = @ptrCast([*:0]const u8, &node.name);
        const node_name = node_name_cstr[0..kernel.cstr_len(node_name_cstr)];
        if (node_name.len == 0) @panic("file not found: no files");

        log.debug("Node name: {s}", .{node_name});

        if (kernel.string_eq(node_name, name)) {
            return SeekResult{
                .sector = sector,
                .node = node.*,
            };
        }

        log.debug("Node size: {}", .{node.size});
        const sectors_to_add = 1 + kernel.bytes_to_sector(node.size);
        log.debug("Sectors to add: {}", .{sectors_to_add});
        sector += sectors_to_add;
    }
}

pub fn read_file(fs_driver: *Filesystem, name: []const u8) []const u8 {
    log.debug("About to read a file...", .{});
    if (seek_file(fs_driver, name)) |seek_result| {
        const file_allocation = kernel.heap.allocate(seek_result.node.size, true, true) orelse @panic("unable to allocate file buffer");
        const file_buffer = @intToPtr([*]u8, file_allocation.virtual)[0..file_allocation.given_size];
        const sectors_to_read = kernel.bytes_to_sector(seek_result.node.size);
        // Add one to skip the metadata
        const sectors_read = fs_driver.disk.read_callback(fs_driver.disk, file_buffer, seek_result.sector + 1, sectors_to_read);
        if (sectors_read != sectors_to_read) @panic("driver failure");

        return file_buffer[0..seek_result.node.size];
    } else {
        @panic("unable to find file");
    }
}

pub const SeekResult = struct {
    sector: u64,
    node: RNUFS.Node,
};
