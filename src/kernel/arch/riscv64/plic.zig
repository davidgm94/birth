const std = @import("std");
const kernel = @import("../../kernel.zig");
const plic = 0x0c00_0000;
const priority = @intToPtr([*]volatile u32, plic);
const pending = @intToPtr(*volatile u32, 0x0c00_1000);
const int_enable = @intToPtr(*volatile u32, 0x0c00_2000);
const threshold = @intToPtr(*volatile u32, 0x0c20_0000);
const claim = @intToPtr(*volatile u32, 0x0c20_0004);

// TODO: consider hart id here
const s_priority = @intToPtr(*volatile u32, plic + 0x201000);
const s_enable = @intToPtr(*volatile u32, plic + 0x2080);
const s_claim = @intToPtr(*volatile u32, plic + 0x201004);

const uart = kernel.arch.uart;
const virtio = kernel.arch.virtio;

const uart_irq = 10;

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
    set_priority(1, 1);
    set_priority(2, 1);
    set_priority(3, 1);
    set_priority(4, 1);
    set_priority(5, 1);
    set_priority(6, 1);
    set_priority(7, 1);
    set_priority(8, 1);
    set_priority(9, 1);
    set_priority(10, 1);

    const hart_id = kernel.arch.hart_id();
    kernel.assert(@src(), hart_id == 0);
    comptime var i: u4 = 0;
    inline while (i <= 10) : (i += 1) {
        s_enable.* = 1 << i;
    }

    s_priority.* = 0;

    //comptime var i: u6 = 1;
    //inline while (i <= 10) : (i += 1) {
    //enable(i);
    //set_priority(i, 1);
    //}
    //set_threshold(0);

    logger.info("PLIC initialized", .{});
}

fn get_next() ?u32 {
    const claim_number = s_claim.*;
    return if (claim_number == 0) return null else claim_number;
}

fn complete(interrupt_number: u32) void {
    s_claim.* = interrupt_number;
}

pub fn handle_interrupt() void {
    if (get_next()) |interrupt| {
        switch (interrupt) {
            1...8 => virtio.handle_interrupt(interrupt),
            10 => uart.handle_interrupt(),
            else => while (true) {},
        }

        complete(interrupt);
    } else @panic("not an interrupt in the queue");
}
