const StackTrace = @import("std").builtin.StackTrace;
const logf = @import("kernel.zig").logf;
const spin = @import("kernel.zig").arch.spin;

pub fn panic(msg: []const u8, _: ?*StackTrace) noreturn
{
    logf("PANIC!\n{s}\n", .{msg}); 
    spin();
}
