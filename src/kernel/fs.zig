const kernel = @import("kernel.zig");
const fs = @import("../common/fs.zig");
const TODO = kernel.TODO;
const log = kernel.log.scoped(.FS);

pub const Driver = struct {
    read: fn (buffer: []u8, sector_start: u64, sector_count: u64) u64,
};

var search_buffer: [kernel.arch.sector_size]u8 = undefined;

const SeekResult = struct {
    sector: u64,
    node: fs.Node,
};

pub fn seek_file(driver: Driver, name: []const u8) ?SeekResult {
    const sectors_to_read_at_time = 1;
    var sector: u64 = 0;
    while (true) {
        log.debug("FS driver asking read", .{});
        const sectors_read = driver.read(&search_buffer, sector, sectors_to_read_at_time);
        if (sectors_read != sectors_to_read_at_time) @panic("driver failure");
        var node = @ptrCast(*fs.Node, @alignCast(@alignOf(fs.Node), &search_buffer));
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

        sector += 1 + kernel.bytes_to_sector(node.size);
    }
}

pub fn read_file(driver: Driver, name: []const u8) []const u8 {
    if (seek_file(driver, name)) |seek_result| {
        const file_allocation = kernel.heap.allocate(seek_result.node.size, true, true) orelse @panic("unable to allocate file buffer");
        const file_buffer = @intToPtr([*]u8, file_allocation.virtual)[0..file_allocation.given_size];
        const sectors_to_read = kernel.bytes_to_sector(seek_result.node.size);
        const sectors_read = driver.read(file_buffer, seek_result.sector, sectors_to_read);
        if (sectors_read != sectors_to_read) @panic("driver failure");

        return file_buffer[0..seek_result.node.size];
    } else {
        @panic("unable to find file");
    }
}
