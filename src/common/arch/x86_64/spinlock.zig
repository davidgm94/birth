const Spinlock = @This();

const common = @import("../../../common.zig");

const log = common.log.scoped(.Spinlock_x86_64);
const AtomicRmwOp = common.AtomicRmwOp;

status: u8 = 0,
were_interrupts_enabled: u8 = 0,

pub fn acquire(spinlock: *volatile Spinlock) void {
    const are_interrupts_enabled = @boolToInt(common.arch.are_interrupts_enabled());
    common.arch.disable_interrupts();
    const expected: @TypeOf(spinlock.status) = 0;
    //spinlock.assert_lock_status(expected);
    if (common.arch.get_current_thread().cpu) |current_cpu| {
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
    if (common.arch.get_current_thread().cpu) |current_cpu| {
        current_cpu.spinlock_count -= 1;
    }
    spinlock.assert_lock_status(expected);
    const were_interrupts_enabled = spinlock.were_interrupts_enabled;
    @fence(.Release);
    spinlock.status = 0;
    //const result = @cmpxchgStrong(@TypeOf(spinlock.status), @ptrCast(*bool, &spinlock.status), expected, !expected, .Release, .Monotonic);
    //common.runtime_assert(@src(), result == null);
    //common.runtime_assert(@src(), result == null);
    if (were_interrupts_enabled != 0) {
        common.arch.enable_interrupts();
    }
}

inline fn assert_lock_status(spinlock: *volatile Spinlock, expected_status: u8) void {
    if (expected_status != spinlock.status or common.arch.are_interrupts_enabled()) @panic("Spinlock not in a desired state");
}
