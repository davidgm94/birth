const std = @import("std");
const arch = @import("arch/x86_64.zig");
const puts = @import("root").puts;


pub fn panic(msg: []const u8, _: ?*std.builtin.StackTrace) noreturn
{
    puts("PANIC!\n");
    puts(msg);
    arch.spin();
}

pub fn kmain() noreturn
{
    arch.set_cpu_local_storage(0);
    puts("\x1b[31mHello, \x1b[33mworld!\x1b[0m\n");
    arch.spin();
}
