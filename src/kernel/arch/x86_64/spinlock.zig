const Spinlock = @This();

const kernel = @import("../../kernel.zig");
const builtin = @import("builtin");
const AtomicRmwOp = builtin.AtomicRmwOp;
status: bool,

pub fn acquire(spinlock: *Spinlock) void {
    const expected = false;
    spinlock.assert_lock_status(expected);
    const result = @atomicRmw(@TypeOf(spinlock.status), &spinlock.status, .Xchg, !expected, .Acquire);
    kernel.assert(@src(), result == expected);
}

pub fn release(spinlock: *Spinlock) void {
    const expected = true;
    spinlock.assert_lock_status(expected);
    const result = @atomicRmw(@TypeOf(spinlock.status), &spinlock.status, .Xchg, !expected, .Release);
    kernel.assert(@src(), result == expected);
}

inline fn assert_lock_status(spinlock: *Spinlock, expected_status: bool) void {
    if (expected_status != spinlock.status) {
        kernel.panic("Spinlock not in a desired state", .{});
    }
}
