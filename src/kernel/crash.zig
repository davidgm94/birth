const std = @import("../common/std.zig");
const arch = @import("arch.zig");

pub fn TODO() noreturn {
    @panic("TODO");
}

pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    @setCold(true);

    const log = std.log.scoped(.PANIC);
    arch.disable_interrupts();
    log.err(format, arguments);

    var stack_iterator = std.StackIterator.init(@returnAddress(), @frameAddress());
    log.err("Stack trace:", .{});
    var stack_trace_i: u64 = 0;
    while (stack_iterator.next()) |return_address| : (stack_trace_i += 1) {
        if (return_address != 0) {
            log.err("{}: 0x{x}", .{ stack_trace_i, return_address });
        }
    }

    while (true) {
        asm volatile (
            \\cli
            \\hlt
            \\pause
            ::: "memory");
    }
}
