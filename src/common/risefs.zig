//! This is a custom variation of the USTAR filesystem just to get started with
const RiseFS = @This();

const common = @import("../common.zig");
const Allocator = common.CustomAllocator;
const assert = common.assert;
const copy = common.copy;
const cstr_len = common.cstr_len;
const div_ceil = common.div_ceil;
const Filesystem = common.Filesystem;
const log = common.log.scoped(.RiseFS);
const zeroes = common.zeroes;

//const Allocator = std.CustomAllocator;
//const log = std.log.scoped(.RiseFS);

pub const presupposed_sector_size = 0x200;

pub const Superblock = struct {
    signature: [5]u8 = default_signature,
    reserved: [presupposed_sector_size - default_signature.len]u8,
};

pub const default_signature = @ptrCast(*const [5]u8, "RiseFS").*;

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

pub fn write_file(filesystem: anytype, allocator: Allocator, filename: []const u8, file_content: []const u8, extra_context: ?*anyopaque) Filesystem.WriteError!void {
    log.debug("Writing new file: {s}. Size: {}", .{ filename, file_content.len });

    const sector_size = filesystem.disk.sector_size;
    assert(filesystem.disk.buffer.items.len % sector_size == 0);
    assert(presupposed_sector_size == sector_size);
    var sector_offset: u64 = @divExact(@sizeOf(Superblock), sector_size);
    const aligned_node_metadata_size = common.align_forward(@sizeOf(Node), sector_size);
    log.debug("Aligned node metadata size: {}", .{aligned_node_metadata_size});

    switch (common.os) {
        else => {
            // @Error @Warning Skip this for the moment in favor of appending
            {
                log.debug("Seeking file {s}", .{filename});
                //const sectors_to_read_at_time = 1;
                ////var search_buffer: [0x200]u8 align(0x200) = undefined;
                ////assert(search_buffer.len == filesystem.disk.sector_size);

                //switch (filesystem.disk.type) {
                //.memory => {
                //const bytes_to_read_at_a_time = sectors_to_read_at_time * sector_size;
                //var byte_offset = sector_offset * bytes_to_read_at_a_time;

                //if (byte_offset < filesystem.disk.buffer.items.len) {
                //while (true) {
                //log.debug("Byte offset: {}. Disk length: {}", .{ byte_offset, filesystem.disk.buffer.items.len });

                //const bytes = filesystem.disk.buffer.items[byte_offset .. byte_offset + bytes_to_read_at_a_time];
                //const node = @ptrCast(*RiseFS.Node, @alignCast(@alignOf(RiseFS.Node), bytes.ptr));

                //if (node.type == .empty) break;

                //const node_name_cstr = @ptrCast([*:0]const u8, &node.name);
                //const node_name = node_name_cstr[0..cstr_len(node_name_cstr)];
                //if (node_name.len == 0) break;

                //const aligned_node_size = common.align_forward(node.size, sector_size);
                //const bytes_to_add = aligned_node_metadata_size + aligned_node_size;
                //log.debug("Bytes to add: {}", .{bytes_to_add});
                //byte_offset += bytes_to_add;
                //}
                //}
                //},
                //else => unreachable,
                //}
            }

            switch (filesystem.disk.type) {
                .memory => {
                    var node = RiseFS.Node{
                        .size = file_content.len,
                        .name = undefined,
                        .type = .file,
                        .parent = zeroes([100]u8),
                        .last_modification = 0,
                    };

                    assert(node.name.len > filename.len);
                    copy(u8, &node.name, filename);
                    node.name[filename.len] = 0;

                    // TODO: @Warning @Error Care about offsets. For now, for memory disks only append
                    filesystem.disk.buffer.appendSliceAssumeCapacity(common.as_bytes(&node));
                    filesystem.disk.buffer.appendNTimesAssumeCapacity(0, aligned_node_metadata_size - @sizeOf(Node));
                    common.assert(filesystem.disk.buffer.items.len % sector_size == 0);

                    filesystem.disk.buffer.appendSliceAssumeCapacity(file_content);
                    filesystem.disk.buffer.appendNTimesAssumeCapacity(0, common.align_forward(file_content.len, sector_size) - file_content.len);
                    common.assert(filesystem.disk.buffer.items.len % sector_size == 0);
                },
                else => unreachable,
            }
        },
        // Rise
        .freestanding => {
            {
                log.debug("Seeking file {s}", .{filename});
                const sectors_to_read_at_time = 1;
                var search_buffer = filesystem.disk.get_dma_buffer(filesystem.disk, allocator, sectors_to_read_at_time) catch {
                    log.err("Unable to allocate search buffer", .{});
                    @panic("lol");
                };

                log.debug("Search buffer address: 0x{x}", .{search_buffer.virtual_address});

                while (true) {
                    log.debug("FS driver asking read at sector {}", .{sector_offset});
                    const sectors_read = filesystem.disk.access(filesystem.disk, &search_buffer, .{
                        .sector_offset = sector_offset,
                        .sector_count = sectors_to_read_at_time,
                        .operation = .read,
                    }, extra_context);
                    if (sectors_read != sectors_to_read_at_time) @panic("Driver internal error: cannot seek file");
                    //for (search_buffer.address.access([*]const u8)[0..sector_size]) |byte, i| {
                    //if (byte != 0) log.debug("[{}] 0x{x}", .{ i, byte });
                    //}
                    log.debug("Search buffer address: 0x{x}", .{search_buffer.virtual_address});
                    //log.debug("Alignment of node: 0x{x}", .{@alignOf(RiseFS.Node)}); TODO: this crashes stage2 https://github.com/ziglang/zig/issues/12488
                    var node = @intToPtr(*RiseFS.Node, search_buffer.virtual_address);
                    log.debug("Node type: {}", .{node.type});
                    if (node.type == .empty) break;
                    const node_name_cstr = @ptrCast([*:0]const u8, &node.name);
                    const node_name = node_name_cstr[0..cstr_len(node_name_cstr)];
                    if (node_name.len == 0) break;

                    const sectors_to_add = 1 + (div_ceil(u64, node.size, sector_size) catch unreachable);
                    log.debug("Found file with name: {s} and size: {}. Need to skip {} sectors", .{ node_name, node.size, sectors_to_add });
                    sector_offset += sectors_to_add;
                }
            }

            const sector_count = 1 + (div_ceil(u64, file_content.len, filesystem.disk.sector_size) catch unreachable);
            log.debug("Started writing {} sectors at sector offset {}", .{ sector_count, sector_offset });
            var write_buffer = filesystem.disk.get_dma_buffer(filesystem.disk, allocator, sector_count) catch {
                log.err("Unable to allocate write buffer", .{});
                @panic("lol");
            };

            // Copy file metadata
            var node = @intToPtr(*RiseFS.Node, write_buffer.virtual_address);
            node.size = file_content.len;
            assert(filename.len < node.name.len);
            copy(u8, &node.name, filename);
            node.name[filename.len] = 0;
            node.type = .file;
            node.parent = zeroes([100]u8);
            node.last_modification = 0;

            // Copy the actual file content
            copy(u8, @intToPtr([*]u8, write_buffer.virtual_address)[sector_size..write_buffer.total_size], file_content);

            const bytes = filesystem.disk.access(filesystem.disk, &write_buffer, .{
                .sector_offset = sector_offset,
                .sector_count = sector_count,
                .operation = .write,
            }, extra_context);
            log.debug("Wrote {} bytes", .{bytes});
        },
    }
}
