const std = @import("std");
const kernel = @import("kernel.zig");
pub fn panic(comptime format: []const u8, args: anytype) noreturn {
    @setCold(true);
    kernel.arch.disable_interrupts();
    _ = kernel.arch.writer.locked.write("Panic!!! ") catch unreachable;
    kernel.arch.writer.locked.print(format, args) catch unreachable;
    while (true) {}
}

pub fn TODO(src: std.builtin.SourceLocation) noreturn {
    panic("TODO: {s}:{}:{} {s}()\n", .{ src.file, src.line, src.column, src.fn_name });
}
