const Spinlock = @This();

const kernel = @import("../../kernel.zig");
const builtin = @import("builtin");
const log = kernel.log.scoped(.Spinlock_x86_64);
const AtomicRmwOp = builtin.AtomicRmwOp;
status: bool,
were_interrupts_enabled: bool,

pub fn acquire(spinlock: *volatile Spinlock) void {
    const are_interrupts_enabled = kernel.arch.are_interrupts_enabled();
    kernel.arch.disable_interrupts();
    const expected = false;
    spinlock.assert_lock_status(expected);
    if (kernel.arch.get_current_cpu()) |current_cpu| {
        current_cpu.spinlock_count += 1;
    }
    const result = @atomicRmw(@TypeOf(spinlock.status), @ptrCast(*bool, &spinlock.status), .Xchg, !expected, .Acquire);
    spinlock.were_interrupts_enabled = are_interrupts_enabled;
    kernel.assert(@src(), result == expected);
}

pub fn release(spinlock: *volatile Spinlock) void {
    const expected = true;
    if (kernel.arch.get_current_cpu()) |current_cpu| {
        current_cpu.spinlock_count -= 1;
    }
    spinlock.assert_lock_status(expected);
    const were_interrupts_enabled = spinlock.were_interrupts_enabled;
    const result = @atomicRmw(@TypeOf(spinlock.status), @ptrCast(*bool, &spinlock.status), .Xchg, !expected, .Release);
    if (were_interrupts_enabled) {
        kernel.arch.enable_interrupts();
    }
    kernel.assert(@src(), result == expected);
}

inline fn assert_lock_status(spinlock: *volatile Spinlock, expected_status: bool) void {
    if (expected_status != spinlock.status) {
        kernel.panic("Spinlock not in a desired state", .{});
    }
}
