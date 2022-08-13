const Scheduler = @import("scheduler.zig");
const Spinlock = @import("spinlock.zig");
const Thread = @import("thread.zig");

pub var scheduler = Scheduler{
    .lock = Spinlock{},
    .thread_buffer = Thread.Buffer{},
    .all_threads = Thread.List{},
    .active_threads = Thread.List{},
    .paused_threads = Thread.List{},
    .cpus = &.{},
    .initialized_ap_cpu_count = 0,
};
