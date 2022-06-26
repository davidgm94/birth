const kernel = @import("root");
const log = kernel.log.scoped(.PANIC);
const SourceLocation = kernel.SourceLocation;

pub fn panic(comptime format: []const u8, args: anytype) noreturn {
    @setCold(true);
    kernel.arch.disable_interrupts();
    log.err(format, args);
    while (true) {}
}

pub fn TODO(src: SourceLocation) noreturn {
    panic("TODO: {s}:{}:{} {s}()", .{ src.file, src.line, src.column, src.fn_name });
}
