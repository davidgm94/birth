const common = @import("../common.zig");

const log = common.log.scoped(.RNUFS);
const drivers = @import("../drivers.zig");
const Filesystem = drivers.Filesystem;
const RNUFS = common.RNUFS;
const GenericDriver = drivers.Driver;
const Disk = drivers.Disk;
const DMA = drivers.DMA;

const Allocator = common.Allocator;
const VirtualAddressSpace = common.VirtualAddressSpace;

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
                .read_file = read_file,
                .write_new_file = write_new_file,
                .allocator = allocator,
            },
        };

        return driver;
    }
};

pub fn seek_file(fs_driver: *Filesystem, special_context: u64, name: []const u8) ?SeekResult {
    const virtual_address_space = @intToPtr(*VirtualAddressSpace, special_context);
    log.debug("Seeking file {s}", .{name});
    const sectors_to_read_at_time = 1;
    var sector: u64 = 0;
    const sector_size = fs_driver.disk.sector_size;
    // TODO: this should be a driver call to meet the specific requirements of the device. For the moment, we page-align everything to be over-correct
    var search_buffer = fs_driver.disk.get_dma_buffer(fs_driver.disk, fs_driver.allocator, sectors_to_read_at_time) catch {
        log.err("Unable to allocate search buffer", .{});
        return null;
    };

    while (true) {
        log.debug("FS driver asking read", .{});
        const sectors_read = fs_driver.disk.access(fs_driver.disk, @ptrToInt(virtual_address_space), &search_buffer, Disk.Work{
            .sector_offset = sector,
            .sector_count = sectors_to_read_at_time,
            .operation = .read,
        });
        log.debug("FS driver ending read", .{});
        if (sectors_read != sectors_to_read_at_time) common.panic(@src(), "Driver internal error: cannot seek file", .{});
        //for (search_buffer.address.access([*]const u8)[0..sector_size]) |byte, i| {
        //if (byte != 0) log.debug("[{}] 0x{x}", .{ i, byte });
        //}
        var node = search_buffer.address.access(*RNUFS.Node);
        const node_name_cstr = @ptrCast([*:0]const u8, &node.name);
        const node_name = node_name_cstr[0..common.cstr_len(node_name_cstr)];
        if (node_name.len == 0) break;

        log.debug("Node name: {s}", .{node_name});

        if (common.string_eq(node_name, name)) {
            return SeekResult{
                .sector = sector,
                .node = node.*,
            };
        }

        log.debug("Node size: {}", .{node.size});
        const sectors_to_add = 1 + common.bytes_to_sector(node.size, sector_size, .can_be_not_exact);
        log.debug("Sectors to add: {}", .{sectors_to_add});
        sector += sectors_to_add;
    }

    @panic("not found");
}

pub fn read_file(fs_driver: *Filesystem, special_context: u64, name: []const u8) []const u8 {
    const virtual_address_space = @intToPtr(*VirtualAddressSpace, special_context);
    log.debug("About to read a file...", .{});
    if (seek_file(fs_driver, special_context, name)) |seek_result| {
        const sector_size = fs_driver.disk.sector_size;
        const node_size = seek_result.node.size;
        const bytes_to_read = common.align_forward(node_size, sector_size);
        const sector_count = common.bytes_to_sector(bytes_to_read, sector_size, .can_be_not_exact);
        // TODO: @Bug @maybebug maybe allocate in the heap?
        var buffer = fs_driver.disk.get_dma_buffer(fs_driver.disk, fs_driver.allocator, sector_count) catch {
            @panic("Unable to allocate read buffer");
        };
        // Add one to skip the metadata
        const sectors_read = fs_driver.disk.access(fs_driver.disk, @ptrToInt(virtual_address_space), &buffer, Disk.Work{
            .sector_offset = seek_result.sector + 1,
            .sector_count = sector_count,
            .operation = .read,
        });

        if (sectors_read != sector_count) common.panic(@src(), "Driver internal error: cannot read file", .{});

        return buffer.address.access([*]const u8)[0..node_size];
    } else {
        @panic("unable to find file");
    }
}

pub fn write_new_file(fs_driver: *Filesystem, special_context: u64, filename: []const u8, file_content: []const u8) void {
    log.debug("Writing new file: {s}", .{filename});
    var sector: u64 = 0;
    const sector_size = fs_driver.disk.sector_size;
    {
        log.debug("Seeking file {s}", .{filename});
        const sectors_to_read_at_time = 1;
        // TODO: this should be a driver call to meet the specific requirements of the device. For the moment, we page-align everything to be over-correct
        var search_buffer = fs_driver.disk.get_dma_buffer(fs_driver.disk, fs_driver.allocator, sectors_to_read_at_time) catch {
            log.err("Unable to allocate search buffer", .{});
            @panic("lol");
        };

        while (true) {
            log.debug("FS driver asking read at sector {}", .{sector});
            const sectors_read = fs_driver.disk.access(fs_driver.disk, special_context, &search_buffer, Disk.Work{
                .sector_offset = sector,
                .sector_count = sectors_to_read_at_time,
                .operation = .read,
            });
            if (sectors_read != sectors_to_read_at_time) common.panic(@src(), "Driver internal error: cannot seek file", .{});
            //for (search_buffer.address.access([*]const u8)[0..sector_size]) |byte, i| {
            //if (byte != 0) log.debug("[{}] 0x{x}", .{ i, byte });
            //}
            var node = search_buffer.address.access(*RNUFS.Node);
            const node_name_cstr = @ptrCast([*:0]const u8, &node.name);
            const node_name = node_name_cstr[0..common.cstr_len(node_name_cstr)];
            if (node_name.len == 0) break;

            const sectors_to_add = 1 + common.bytes_to_sector(node.size, sector_size, .can_be_not_exact);
            log.debug("Found file with name: {s} and size: {}. Need to skip {} sectors", .{ node_name, node.size, sectors_to_add });
            sector += sectors_to_add;
        }
    }

    const sector_count = common.bytes_to_sector(file_content.len, fs_driver.disk.sector_size, .can_be_not_exact) + 1;
    log.debug("Started writing {} sectors at sector offset {}", .{ sector_count, sector });
    var write_buffer = fs_driver.disk.get_dma_buffer(fs_driver.disk, fs_driver.allocator, sector_count) catch {
        log.err("Unable to allocate write buffer", .{});
        @panic("lol");
    };

    // Copy file metadata
    var node = write_buffer.address.access(*RNUFS.Node);
    node.size = file_content.len;
    common.runtime_assert(@src(), filename.len < node.name.len);
    common.copy(u8, &node.name, filename);
    node.name[filename.len] = 0;
    node.type = .file;
    node.parent = common.zeroes([100]u8);
    node.last_modification = 0;

    // Copy the actual file content
    common.copy(u8, write_buffer.address.access([*]u8)[sector_size..write_buffer.total_size], file_content);

    const bytes = fs_driver.disk.access(fs_driver.disk, special_context, &write_buffer, Disk.Work{
        .sector_offset = sector,
        .sector_count = sector_count,
        .operation = .write,
    });
    log.debug("Wrote {} bytes", .{bytes});
}

pub const SeekResult = struct {
    sector: u64,
    node: RNUFS.Node,
};
