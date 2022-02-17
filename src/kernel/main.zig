const StackTrace = @import("std").builtin.StackTrace;
const logf = @import("kernel.zig").logf;
const spin = @import("kernel.zig").arch.spin;

pub fn panic(msg: []const u8, stack_trace: ?*StackTrace) noreturn
{
    logf("PANIC!\n{s}\nStack trace:\n{}\n", .{msg, stack_trace});
    spin();
}
