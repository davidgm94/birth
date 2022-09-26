const Timer = @This();

const common = @import("common");

const RNU = @import("RNU");
const arch = @import("arch");
const CPU = arch.CPU;

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
            common.log.scoped(ID).info("{} cycles", .{cycles});
        }

        pub fn end_and_custom_log(scoped_timer: *@This(), comptime format: []const u8, args: anytype) void {
            scoped_timer.end_and_log();
            common.log.scoped(ID).debug(format, args);
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
                common.log.scoped(ID).info("Timestamp #{}: {} cycles", .{ i, timestamp - last });
            }

            common.log.scoped(ID).info("Total took {} cycles", .{timer_accumulator.timestamps[timer_accumulator.timestamp_count - 1] - timer_accumulator.base_timestamp});
        }
    };
}

pub const Register = struct {
    timestamps: [1024 * 1024]u64 = undefined,
    count: u64 = 0,
    current_start: u64 = undefined,

    pub inline fn register_start(register: *Register) void {
        register.current_start = CPU.read_timestamp();
    }

    pub inline fn register_end(register: *Register) void {
        defer register.count += 1;
        register.timestamps[register.count] = CPU.read_timestamp() - register.current_start;
    }

    pub fn get_integer_mean(register: *Register) IntegerMean {
        var sum: u64 = 0;
        for (register.timestamps[0..register.count]) |timestamp| {
            sum += timestamp;
        }

        var result: u64 = 0;
        var remainder: u64 = 0;

        if (sum != 0) {
            result = sum / register.count;
            remainder = sum % register.count;
        }

        return IntegerMean{
            .sum = sum,
            .count = register.count,
            .result = result,
            .remainder = remainder,
        };
    }

    const IntegerMean = struct {
        sum: u64,
        count: u64,
        result: u64,
        remainder: u64,
    };
};
