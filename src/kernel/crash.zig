const std = @import("../common/std.zig");
const kernel = @import("kernel.zig");
const interrupts = @import("arch/interrupts.zig");

pub fn TODO() noreturn {
    @panic("TODO");
}

const log = std.log.scoped(.PANIC);
pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    @setCold(true);
    interrupts.disable();
    if (kernel.scheduler.cpus.len > 1) {
        log.err("Panic happened. Stopping all cores...", .{});
        interrupts.send_panic_interrupt_to_all_cpus();
    }

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
