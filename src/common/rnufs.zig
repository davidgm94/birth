//! This is a custom variation of the USTAR filesystem just to get started with
const RNUFS = @This();

const std = @import("std.zig");

const FilesystemInterface = @import("../drivers/filesystem_interface.zig");

const Allocator = std.Allocator;
const log = std.log.scoped(.RNUFS);

pub const Superblock = struct {
    signature: [5]u8 = default_signature,
    reserved: [presupposed_sector_size - 5]u8,
};

pub const default_signature = @ptrCast(*const [5]u8, "RNUFS").*;

pub const Node = struct {
    name: [100]u8,
    parent: [100]u8,
    size: u64,
    last_modification: u64,
    type: NodeType,
};

pub const NodeType = enum(u64) {
    empty = 0,
    file = 1,
    directory = 2,
};

pub const presupposed_sector_size = 0x200;

pub fn write_new_file(fs_driver: *FilesystemInterface, allocator: Allocator, filename: []const u8, file_content: []const u8, extra_context: ?*anyopaque) void {
    log.debug("Writing new file: {s}. Size: {}", .{ filename, file_content.len });

    const sector_size = fs_driver.disk.sector_size;
    std.assert(presupposed_sector_size == sector_size);
    var sector: u64 = std.bytes_to_sector(@sizeOf(Superblock), sector_size, .must_be_exact);
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
            const sectors_read = fs_driver.disk.access(fs_driver.disk, &search_buffer, .{
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
    var write_buffer = fs_driver.disk.get_dma_buffer(fs_driver.disk, allocator, sector_count) catch {
        log.err("Unable to allocate write buffer", .{});
        @panic("lol");
    };

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

    const bytes = fs_driver.disk.access(fs_driver.disk, &write_buffer, .{
        .sector_offset = sector,
        .sector_count = sector_count,
        .operation = .write,
    }, extra_context);
    log.debug("Wrote {} bytes", .{bytes});
}
