const std = @import("std");
const assert = std.debug.assert;
const fs = @import("../common/fs.zig");

const log = std.log_scoped(.build_fs);

pub const MemoryDisk = struct {
    bytes: []u8,
};

const sector_size = 0x200;

pub fn add_file(disk: MemoryDisk, name: []const u8, content: []const u8) void {
    var it = disk.bytes;
    _ = name;
    _ = content;
    while (it[0] != 0) : (it = it[sector_size..]) {
        unreachable;
    }

    var node = @ptrCast(*fs.Node, @alignCast(@alignOf(fs.Node), it.ptr));
    node.size = content.len;
    assert(name.len < node.name.len);
    std.mem.copy(u8, &node.name, name);
    node.name[name.len] = 0;
    node.type = .file;
    node.parent = std.mem.zeroes([100]u8);
    node.last_modification = 0;

    const left = it[sector_size..];
    assert(left.len > content.len);
    std.mem.copy(u8, left, content);
}

pub fn read_debug(disk: MemoryDisk) void {
    var node = @ptrCast(*fs.Node, @alignCast(@alignOf(fs.Node), disk.bytes.ptr));
    log.debug("Node size: {}. Node name: {s}", .{ node.size, node.name });
    log.debug("First bytes:", .{});
    for (disk.bytes[sector_size .. sector_size + 0x20]) |byte, i| {
        log.debug("[{}]: 0x{x}", .{ i, byte });
    }
}
