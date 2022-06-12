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
};
