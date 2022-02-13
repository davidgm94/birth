const std = @import("std");
const arch = @import("arch/x86_64.zig");
const stivale = @import("stivale2.zig");

pub fn log(str: []const u8) void
{
    stivale.terminal_write(str);
    arch.write_to_debug_port(str);
}

pub fn panic(msg: []const u8, _: ?*std.builtin.StackTrace) noreturn
{
    log("PANIC!\n");
    log(msg);
    arch.spin();
}

pub fn main() noreturn
{
    arch.set_cpu_local_storage(0);
    arch.fpu_flags();
    log("\x1b[31mHello, \x1b[33mworld!\x1b[0m\n");
    arch.spin();
}
