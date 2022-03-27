const std = @import("std");
const priority = @intToPtr([*]volatile u32, 0x0c00_0000);
const pending = @intToPtr(*volatile u32, 0x0c00_1000);
const int_enable = @intToPtr(*volatile u32, 0x0c00_2000);
const threshold = @intToPtr(*volatile u32, 0x0c20_0000);
const claim = @intToPtr(*volatile u32, 0x0c20_0004);

const logger = std.log.scoped(.PLIC);

pub fn set_threshold(asked_threshold: u3) void {
    threshold.* = asked_threshold;
}

pub fn enable(comptime id: u6) void {
    const actual_id: u32 = 1 << id;

    const value = int_enable.* | actual_id;
    int_enable.* = value;
}

pub fn set_priority(comptime id: u6, comptime asked_priority: u3) void {
    const ptr = priority + id;
    ptr.* = asked_priority;
}

pub fn init() void {
    set_threshold(0);
    comptime var i: u6 = 1;
    inline while (i <= 10) : (i += 1) {
        enable(i);
        set_priority(i, 1);
    }

    logger.info("PLIC initialized", .{});
}
