const std = @import("std");
const kernel = @import("kernel.zig");

const log = kernel.log.scoped(.PANIC);

pub fn panic(comptime format: []const u8, args: anytype) noreturn {
    @setCold(true);
    kernel.arch.disable_interrupts();
    kernel.arch.Writer.should_lock = true;
    kernel.arch.writer.print(format, args) catch unreachable;
    while (true) {}
}

pub fn TODO(src: std.builtin.SourceLocation) noreturn {
    panic("TODO: {s}:{}:{} {s}()\n", .{ src.file, src.line, src.column, src.fn_name });
}
