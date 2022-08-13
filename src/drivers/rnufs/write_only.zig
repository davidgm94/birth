const std = @import("../../common/std.zig");
const log = std.log.scoped(.RNUFS);
const RNUFS = @import("../../common/rnufs.zig");
const Filesystem = @import("../filesystem.zig");
const GenericDriver = @import("../../drivers.zig").GenericDriver;
const Disk = @import("../disk.zig");
const DMA = @import("../dma.zig");

const Allocator = std.Allocator;

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
                .read_file = undefined,
                .write_new_file = write_new_file,
            },
        };

        return driver;
    }
};

pub fn write_new_file(fs_driver: *Filesystem, allocator: Allocator, filename: []const u8, file_content: []const u8, extra_context: ?*anyopaque) void {
    log.debug("Writing new file: {s}. Size: {}", .{ filename, file_content.len });
    var sector: u64 = 0;
    const sector_size = fs_driver.disk.sector_size;
    {
        log.debug("Seeking file {s}", .{filename});
        const sectors_to_read_at_time = 1;
        var search_buffer = fs_driver.disk.get_dma_buffer(fs_driver.disk, allocator, sectors_to_read_at_time) catch {
            log.err("Unable to allocate search buffer", .{});
            @panic("lol");
        };
        log.debug("Search buffer address: 0x{x}", .{search_buffer.address});

        while (true) {
            log.debug("FS driver asking read at sector {}", .{sector});
            const sectors_read = fs_driver.disk.access(fs_driver.disk, &search_buffer, Disk.Work{
                .sector_offset = sector,
                .sector_count = sectors_to_read_at_time,
                .operation = .read,
            }, extra_context);
            if (sectors_read != sectors_to_read_at_time) @panic("Driver internal error: cannot seek file");
            //for (search_buffer.address.access([*]const u8)[0..sector_size]) |byte, i| {
            //if (byte != 0) log.debug("[{}] 0x{x}", .{ i, byte });
            //}
            log.debug("Search buffer address: 0x{x}", .{search_buffer.address});
            log.debug("Alignment of node: 0x{x}", .{@alignOf(RNUFS.Node)});
            var node = @intToPtr(*RNUFS.Node, search_buffer.address);
            log.debug("Node type: {}", .{node.type});
            if (node.type == .empty) break;
            const node_name_cstr = @ptrCast([*:0]const u8, &node.name);
            const node_name = node_name_cstr[0..std.cstr_len(node_name_cstr)];
            if (node_name.len == 0) break;

            const sectors_to_add = 1 + std.bytes_to_sector(node.size, sector_size, .can_be_not_exact);
            log.debug("Found file with name: {s} and size: {}. Need to skip {} sectors", .{ node_name, node.size, sectors_to_add });
            sector += sectors_to_add;
        }
    }

    const sector_count = std.bytes_to_sector(file_content.len, fs_driver.disk.sector_size, .can_be_not_exact) + 1;
    log.debug("Started writing {} sectors at sector offset {}", .{ sector_count, sector });
    var write_buffer = fs_driver.disk.get_dma_buffer(fs_driver.disk, allocator, sector_count) catch @panic("Unable to allocate write buffer");

    // Copy file metadata
    var node = @intToPtr(*RNUFS.Node, write_buffer.address);
    node.size = file_content.len;
    std.assert(filename.len < node.name.len);
    std.copy(u8, &node.name, filename);
    node.name[filename.len] = 0;
    node.type = .file;
    node.parent = std.zeroes([100]u8);
    node.last_modification = 0;

    // Copy the actual file content
    std.copy(u8, @intToPtr([*]u8, write_buffer.address)[sector_size..write_buffer.total_size], file_content);

    const bytes = fs_driver.disk.access(fs_driver.disk, &write_buffer, Disk.Work{
        .sector_offset = sector,
        .sector_count = sector_count,
        .operation = .write,
    }, extra_context);
    log.debug("Wrote {} bytes", .{bytes});
}
