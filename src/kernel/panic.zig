const std = @import("std");
const kernel = @import("kernel.zig");

const log = kernel.log.scoped(.PANIC);

pub const SourceLocation = std.builtin.SourceLocation;

pub fn panic(comptime format: []const u8, args: anytype) noreturn {
    @setCold(true);
    kernel.arch.disable_interrupts();
    kernel.arch.Writer.should_lock = true;
    log.err(format, args);
    while (true) {}
}

pub fn TODO(src: SourceLocation) noreturn {
    panic("TODO: {s}:{}:{} {s}()\n", .{ src.file, src.line, src.column, src.fn_name });
}
