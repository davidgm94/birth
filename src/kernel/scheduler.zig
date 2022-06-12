const kernel = @import("kernel.zig");
const TODO = kernel.TODO;
const log = kernel.log.scoped(.Scheduler);

pub const Context = kernel.arch.Context;

pub fn new_fn() noreturn {
    while (true) {
        log.debug("new process", .{});
    }
}

var lock: kernel.arch.Spinlock = undefined;
var thread_pool: [8192]Thread = undefined;
var thread_id: u64 = 0;

pub fn yield(context: *Context) void {
    _ = context;
    kernel.arch.disable_interrupts();
    lock.acquire();
    if (lock.were_interrupts_enabled) @panic("ffff");
    var new_thread_foo: Thread = undefined;
    kernel.arch.switch_context(context, &kernel.address_space.arch, 0, &new_thread_foo, &kernel.address_space);
}

pub const Thread = struct {
    todo: u64,

    const ThreadType = enum(u1) {
        kernel = 0,
        user = 1,
    };

    // TODO: idle thread
    const Idle = enum(u1) {
        no = 0,
        yes = 1,
    };

    pub fn spawn(thread_type: ThreadType) Thread {
        // TODO: lock
        var thread = &thread_pool[thread_id % thread_pool.len];
        thread_id += 1;

        var kernel_stack_size: u64 = 0x5000;
        const user_stack_reserve: u64 = switch (thread_type) {
            .kernel => kernel_stack_size,
            .user => 0x400000,
        };
        const user_stack_commit: u64 = switch (thread_type) {
            .kernel => 0,
            .user => 0x10000,
        };
        _ = thread;
        _ = user_stack_reserve;
        _ = user_stack_commit;

        unreachable;
    }
};

pub fn init() void {}
