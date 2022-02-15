const StackTrace = @import("std").builtin.StackTrace;
const log = @import("kernel").log;
const spin = @import("kernel").arch.spin;

pub fn panic(msg: []const u8, _: ?*StackTrace) noreturn
{
    log("PANIC!\n");
    log(msg);
    spin();
}
