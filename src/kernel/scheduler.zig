const kernel = @import("kernel.zig");
const TODO = kernel.TODO;
const log = kernel.log.scoped(.Scheduler);

const Virtual = kernel.Virtual;

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
    privilege_level: PrivilegeLevel,
    type: Type,
    kernel_stack: Virtual.Address,
    user_stack: Virtual.Address,
    user_stack_reserve: u64,
    user_stack_commit: u64,
    id: u64,
    context: *kernel.arch.Context,

    const PrivilegeLevel = enum(u1) {
        kernel = 0,
        user = 1,
    };

    // TODO: idle thread
    const Type = enum(u1) {
        normal = 0,
        idle = 1,
    };

    pub const EntryPoint = struct {
        start_address: u64,
        argument: u64,
    };

    pub fn spawn(privilege_level: PrivilegeLevel, entry_point: EntryPoint) *Thread {
        // TODO: lock
        const new_thread_id = thread_id;
        const thread_index = new_thread_id % thread_pool.len;
        var thread = &thread_pool[thread_index];
        thread_id += 1;

        var kernel_stack_size: u64 = 0x5000;
        const user_stack_reserve: u64 = switch (privilege_level) {
            .kernel => kernel_stack_size,
            .user => 0x400000,
        };
        const user_stack_commit: u64 = switch (privilege_level) {
            .kernel => 0,
            .user => 0x10000,
        };
        var user_stack: Virtual.Address = undefined;
        // TODO: implemented idle thread

        const kernel_stack = kernel.address_space.allocate(kernel_stack_size) orelse @panic("unable to allocate the kernel stack");
        switch (privilege_level) {
            .kernel => {
                user_stack = kernel_stack;
            },
            .user => {
                TODO(@src());
            },
        }
        thread.privilege_level = privilege_level;
        thread.kernel_stack = kernel_stack;
        thread.user_stack = user_stack;
        thread.user_stack_reserve = user_stack_reserve;
        thread.user_stack_commit = user_stack_commit;
        thread.id = new_thread_id;
        thread.type = .normal;
        kernel.assert(@src(), thread.type == .normal);

        if (thread.type != .idle) {
            thread.context = kernel.arch.Context.new(thread, entry_point);
        }
        _ = thread;
        _ = user_stack_reserve;
        _ = user_stack_commit;

        return thread;
    }
};

fn dummy_thread(arg: u64) void {
    _ = arg;
    while (true) {
        log.debug("WE ARE PRINTING", .{});
    }
}

pub fn init() void {
    const thread = Thread.spawn(.kernel, Thread.EntryPoint{
        .start_address = @ptrToInt(dummy_thread),
        .argument = 0,
    });
    _ = thread;
}
