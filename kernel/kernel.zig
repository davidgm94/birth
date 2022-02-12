const std = @import("std");
const puts = @import("root").puts;

fn spin() noreturn {
    while (true) {
        std.atomic.spinLoopHint();
    }
}

pub fn panic(msg: []const u8, _: ?*std.builtin.StackTrace) noreturn {
    puts("PANIC!\n");
    puts(msg);
    spin();
}

pub fn kmain() noreturn {
    puts("\x1b[31mHello, \x1b[33mworld!\x1b[0m\n");
    spin();
}
