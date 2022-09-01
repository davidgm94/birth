const std = @import("../common/std.zig");
const kernel = @import("kernel.zig");
const interrupts = @import("arch/interrupts.zig");

pub fn TODO() noreturn {
    @panic("TODO");
}

const log = std.log.scoped(.PANIC);
pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    @setCold(true);
    panic_extended(format, arguments, @returnAddress(), @frameAddress());
}

pub fn panic_extended(comptime format: []const u8, arguments: anytype, start_address: usize, maybe_frame_pointer: ?usize) noreturn {
    @setCold(true);
    interrupts.disable();
    if (kernel.scheduler.cpus.len > 1) {
        log.err("Panic happened. Stopping all cores...", .{});
        interrupts.send_panic_interrupt_to_all_cpus();
    }

    log.err(format, arguments);

    dump_stack_trace(start_address, maybe_frame_pointer);

    while (true) {
        asm volatile (
            \\cli
            \\hlt
            \\pause
            ::: "memory");
    }
}

const use_zig_stack_iterator = false;

pub fn dump_stack_trace(start_address: usize, maybe_frame_pointer: ?usize) void {
    const frame_pointer = if (maybe_frame_pointer) |frame_pointer| frame_pointer else @frameAddress();

    if (use_zig_stack_iterator) {
        var stack_iterator = std.StackIterator.init(start_address, frame_pointer);
        log.err("Stack trace:", .{});
        var stack_trace_i: u64 = 0;
        while (stack_iterator.next()) |return_address| : (stack_trace_i += 1) {
            if (return_address != 0) {
                log.err("{}: 0x{x}", .{ stack_trace_i, return_address });
            }
        }
    } else {
        log.debug("============= STACK TRACE =============", .{});
        var ip = start_address;
        var stack_trace_depth: u64 = 0;
        var maybe_bp = @intToPtr(?[*]usize, frame_pointer);
        while (true) {
            defer stack_trace_depth += 1;
            if (ip != 0) log.debug("{}: 0x{x}", .{ stack_trace_depth, ip });
            if (maybe_bp) |bp| {
                ip = bp[1];
                maybe_bp = @intToPtr(?[*]usize, bp[0]);
            } else {
                break;
            }
        }

        log.debug("============= STACK TRACE =============", .{});
    }
}
