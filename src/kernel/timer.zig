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

pub fn Scoped(comptime ID: @TypeOf(.EnumLiteral)) type {
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

pub fn Accumulator(comptime ID: @TypeOf(.EnumLiteral), comptime array_size: comptime_int) type {
    return struct {
        timestamps: [array_size]u64 = undefined,
        timestamp_count: u64 = 0,
        base_timestamp: u64,

        pub fn new() @This() {
            return @This(){
                .base_timestamp = CPU.read_timestamp(),
            };
        }

        pub fn register(timer_accumulator: *@This()) void {
            defer timer_accumulator.timestamp_count += 1;
            timer_accumulator.timestamps[timer_accumulator.timestamp_count] = CPU.read_timestamp();
        }

        pub fn end_by_logging(timer_accumulator: *@This(), comptime register_at_the_end: bool) void {
            if (register_at_the_end) {
                timer_accumulator.register();
            }

            var last = timer_accumulator.base_timestamp;
            for (timer_accumulator.timestamps[0..timer_accumulator.timestamp_count]) |timestamp, i| {
                defer last = timestamp;
                std.log.scoped(ID).info("Timestamp #{}: {} cycles", .{ i, timestamp - last });
            }

            std.log.scoped(ID).info("Total took {} cycles", .{timer_accumulator.timestamps[timer_accumulator.timestamp_count - 1] - timer_accumulator.base_timestamp});
        }
    };
}
