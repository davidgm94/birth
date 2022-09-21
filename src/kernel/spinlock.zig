const Spinlock = @This();

const std = @import("../common/std.zig");

const interrupts = @import("arch/interrupts.zig");
const TLS = @import("arch/tls.zig");
const log = std.log.scoped(.Spinlock);
const AtomicRmwOp = std.AtomicRmwOp;

status: u8 = 0,
were_interrupts_enabled: u8 = 0,

pub fn acquire(spinlock: *volatile Spinlock) void {
    const are_interrupts_enabled = @boolToInt(interrupts.are_enabled());
    interrupts.disable();
    const expected: @TypeOf(spinlock.status) = 0;
    spinlock.assert_lock_status(expected);
    if (TLS.get_current().cpu) |current_cpu| {
        current_cpu.spinlock_count += 1;
    }

    while (@cmpxchgStrong(@TypeOf(spinlock.status), @ptrCast(*@TypeOf(spinlock.status), &spinlock.status), expected, ~expected, .Acquire, .Monotonic) != null) {
        asm volatile ("pause" ::: "memory");
    }

    @fence(.Acquire);

    spinlock.were_interrupts_enabled = are_interrupts_enabled;
}

pub fn release(spinlock: *volatile Spinlock) void {
    const expected = ~@as(@TypeOf(spinlock.status), 0);
    if (TLS.get_current().cpu) |current_cpu| {
        current_cpu.spinlock_count -= 1;
    }
    spinlock.assert_lock_status(expected);
    const were_interrupts_enabled = spinlock.were_interrupts_enabled;
    @fence(.Release);
    spinlock.status = 0;
    if (were_interrupts_enabled != 0) {
        interrupts.enable();
    }
}

inline fn assert_lock_status(spinlock: *volatile Spinlock, expected_status: u8) void {
    if (expected_status != spinlock.status or interrupts.are_enabled()) @panic("Spinlock not in a desired state");
}

pub fn assert_locked(spinlock: *volatile Spinlock) void {
    if (spinlock.status != ~@as(@TypeOf(spinlock.status), 0)) @panic("Spinlock not locked when must be");
}

pub fn format(spinlock: *const Spinlock, comptime _: []const u8, _: std.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
    try std.internal_format(writer, "{s}", .{if (spinlock.status == 0xff) "locked" else if (spinlock.status == 0) "unlocked" else "invalid"});
}
