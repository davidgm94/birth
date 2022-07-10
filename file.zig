const std = @import("std");

pub fn main() !void {
    const file = try std.fs.cwd().readFileAlloc(std.heap.c_allocator, "zig-cache/minimal.elf", 0xffff_ffff_ffff_ffff);
    var new_file_buffer = std.ArrayList(u8).init(std.heap.c_allocator);
    var buffer: [1024]u8 = undefined;
    for (file) |byte, i| {
        try new_file_buffer.appendSlice(try std.fmt.bufPrint(&buffer, "[{}] = 0x{x}\n", .{ i, byte }));
    }

    try std.fs.cwd().writeFile("debug_file", new_file_buffer.items);
}
