const Timer = @This();

const std = @import("../common/std.zig");

const common = @import("./arch/common.zig");
const CPU = common.CPU;

timer_start: u64,
timer_end: u64,

pub fn new() Timer {
    return Timer{
        .timer_start = CPU.read_timestamp(),
        .timer_end = 0,
    };
}

fn end(timer: *Timer) void {
    timer.timer_end = CPU.read_timestamp();
}

pub fn end_and_get_metric(timer: *Timer) u64 {
    timer.end();
    return timer.timer_end - timer.timer_start;
}

pub fn ScopedTimer(comptime ID: @TypeOf(.EnumLiteral)) type {
    return struct {
        timer: Timer,

        pub fn start() @This() {
            return @This(){
                .timer = Timer.new(),
            };
        }

        pub fn end_and_log(scoped_timer: *@This()) void {
            const cycles = scoped_timer.timer.end_and_get_metric();
            std.log.scoped(ID).info("{} cycles", .{cycles});
        }

        pub fn end_and_custom_log(scoped_timer: *@This(), comptime format: []const u8, args: anytype) void {
            scoped_timer.end_and_log();
            std.log.scoped(ID).debug(format, args);
        }
    };
}
