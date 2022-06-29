const kernel = @import("root");
const common = @import("common");

const log = common.log.scoped(.RNUFS);
const drivers = kernel.drivers;
const Filesystem = drivers.Filesystem;
const RNUFS = @import("../common/fs.zig");
const GenericDriver = drivers.Driver;
const Disk = drivers.Disk;
const DMA = drivers.DMA;

const Allocator = common.Allocator;

const Driver = @This();

fs: Filesystem,

pub const Initialization = struct {
    pub const Context = *Disk;
    pub const Error = error{
        allocation_failure,
    };

    pub fn callback(allocator: Allocator, initialization_context: Context) Filesystem.InitializationError!*Driver {
        const driver = allocator.create(Driver) catch return Error.allocation_failure;
        driver.* = Driver{
            .fs = Filesystem{
                .type = .RNU,
                .disk = initialization_context,
                .read_file_callback = read_file,
                .allocator = allocator,
            },
        };

        return driver;
    }
};

pub fn seek_file(fs_driver: *Filesystem, name: []const u8) ?SeekResult {
    log.debug("Seeking file {s}", .{name});
    const sectors_to_read_at_time = 1;
    var sector: u64 = 0;
    const sector_size = fs_driver.disk.sector_size;
    log.debug("Initializing search buffer", .{});
    // TODO: this should be a driver call to meet the specific requirements of the device. For the moment, we page-align everything to be over-correct
    var search_buffer = DMA.Buffer.new(fs_driver.allocator, .{ .size = kernel.align_forward(sector_size, kernel.arch.page_size), .alignment = kernel.align_forward(sector_size, kernel.arch.page_size) }) catch @panic("unable to initialize buffer");
    log.debug("Done initializing search buffer", .{});

    while (true) {
        log.debug("FS driver asking read", .{});
        const sectors_read = fs_driver.disk.access(fs_driver.disk, &search_buffer, Disk.Work{
            .sector_offset = sector,
            .sector_count = sectors_to_read_at_time,
            .operation = .read,
        });
        log.debug("FS driver ending read", .{});
        if (sectors_read != sectors_to_read_at_time) kernel.crash("Driver internal error: cannot seek file", .{});
        for (search_buffer.address.access([*]const u8)[0..sector_size]) |byte, i| {
            if (byte != 0) log.debug("[{}] 0x{x}", .{ i, byte });
        }
        var node = search_buffer.address.access(*RNUFS.Node);
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
        // TODO: this should be a driver call to meet the specific requirements of the device. For the moment, we page-align everything to be over-correct
        var buffer = DMA.Buffer.new(fs_driver.allocator, .{ .size = kernel.align_forward(bytes_to_read, kernel.arch.page_size), .alignment = kernel.align_forward(sector_size, kernel.arch.page_size) }) catch @panic("unable to initialize buffer");
        const sectors_to_read = kernel.bytes_to_sector(bytes_to_read, sector_size, .must_be_exact);
        // Add one to skip the metadata
        const sectors_read = fs_driver.disk.access(fs_driver.disk, &buffer, Disk.Work{
            .sector_offset = seek_result.sector + 1,
            .sector_count = sectors_to_read,
            .operation = .read,
        });

        if (sectors_read != sectors_to_read) kernel.crash("Driver internal error: cannot read file", .{});

        return buffer.address.access([*]const u8)[0..node_size];
    } else {
        @panic("unable to find file");
    }
}

pub const SeekResult = struct {
    sector: u64,
    node: RNUFS.Node,
};
