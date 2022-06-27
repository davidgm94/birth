const kernel = @import("root");
const log = kernel.log_scoped(.RNUFS);
const drivers = kernel.drivers;
const Filesystem = drivers.Filesystem;
const RNUFS = @import("../common/fs.zig");
const GenericDriver = drivers.Driver;
const Disk = drivers.Disk;
const DMA = drivers.DMA;

const Driver = @This();

fs: Filesystem,

pub const Initialization = struct {
    pub const Context = *Disk;
    pub const Error = error{
        allocation_failure,
    };

    pub fn callback(allocator: kernel.Allocator, initialization_context: Context) Filesystem.InitializationError!*Driver {
        const driver = allocator.create(Driver) catch return Error.allocation_failure;
        driver.fs.disk = initialization_context;
        driver.fs.read_file_callback = read_file;

        return driver;
    }
};

pub fn seek_file(fs_driver: *Filesystem, name: []const u8) ?SeekResult {
    const sectors_to_read_at_time = 1;
    var sector: u64 = 0;
    const sector_size = fs_driver.disk.sector_size;
    var search_buffer = DMA.Buffer.new(fs_driver.allocator, .{ .size = sector_size, .alignment = sector_size }) catch @panic("unable to initialize buffer");

    while (true) {
        log.debug("FS driver asking read", .{});
        const sectors_read = fs_driver.disk.access(fs_driver.disk, &search_buffer, Disk.Work{
            .sector_offset = sector,
            .sector_count = sectors_to_read_at_time,
            .operation = .read,
        });
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
        const sectors_to_add = 1 + kernel.bytes_to_sector(node.size, sector_size, .can_be_not_exact);
        log.debug("Sectors to add: {}", .{sectors_to_add});
        sector += sectors_to_add;
    }
}

pub fn read_file(fs_driver: *Filesystem, name: []const u8) []const u8 {
    log.debug("About to read a file...", .{});
    if (seek_file(fs_driver, name)) |seek_result| {
        const node_size = seek_result.node.size;
        const sector_size = fs_driver.disk.sector_size;
        const bytes_to_read = kernel.align_forward(node_size, sector_size);
        // TODO: @Bug @maybebug maybe allocate in the heap?
        var buffer = DMA.Buffer.new(fs_driver.allocator, .{ .size = bytes_to_read, .alignment = sector_size }) catch @panic("unable to initialize buffer");
        const sectors_to_read = kernel.bytes_to_sector(bytes_to_read, sector_size, .must_be_exact);
        // Add one to skip the metadata
        const sectors_read = fs_driver.disk.access(fs_driver.disk, &buffer, Disk.Work{
            .sector_offset = seek_result.sector + 1,
            .sector_count = sectors_to_read,
            .operation = .read,
        });

        if (sectors_read != sectors_to_read) @panic("driver failure");

        return buffer.address.access([*]const u8)[0..node_size];
    } else {
        @panic("unable to find file");
    }
}

pub const SeekResult = struct {
    sector: u64,
    node: RNUFS.Node,
};
