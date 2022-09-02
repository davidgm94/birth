const Timer = @This();
const common = @import("./arch/common.zig");
const CPU = common.CPU;

timer_start: u64,
timer_end: u64,

pub inline fn new() Timer {
    return Timer{
        .timer_start = CPU.read_timestamp(),
        .timer_end = 0,
    };
}

inline fn end(timer: *Timer) void {
    timer.timer_end = CPU.read_timestamp();
}

pub inline fn end_and_get_metric(timer: *Timer) u64 {
    timer.end();
    return timer.timer_end - timer.timer_start;
}
