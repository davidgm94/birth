const kernel = @import("../../kernel.zig");
var frequency: u32 = 0;

pub fn init() void {
    const property = kernel.arch.device_tree.find_property("cpus", "timebase-frequency", .exact, null, null) orelse @panic("Couldn't find property timebase-frequency");
    frequency = kernel.arch.dt_read_int(u32, property.value);
}

pub fn get_timestamp() u64 {
    var time: u64 = 0;
    asm volatile ("csrr %[time], time"
        : [time] "=r" (time),
    );
    return time;
}

pub fn get_time_from_timestamp(timestamp: u64) Time {
    return Time{
        .s = timestamp / frequency,
        .us = (timestamp % frequency) * 1000 * 1000 / frequency,
    };
}

fn get_time() Time {
    var time: u64 = 0;
    asm volatile ("csrr %[time], time"
        : [time] "=r" (time),
    );

    return Time{
        .s = time / frequency,
        .us = (time % frequency) * 1000 * 1000 / frequency,
    };
}

const Time = struct {
    s: u64,
    us: u64,
};
