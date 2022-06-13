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

pub fn yield(context: *Context) noreturn {
    if (kernel.arch.get_current_cpu().?.current_thread) |current_thread| {
        current_thread.context = context;
    }
    _ = kernel.arch.are_interrupts_enabled();
    kernel.arch.disable_interrupts();
    lock.acquire();
    if (lock.were_interrupts_enabled) @panic("ffff");
    const new_thread = pick_thread();
    new_thread.time_slices += 1;
    // TODO: idle
    lock.release();

    kernel.arch.next_timer(1);
    kernel.arch.switch_context(new_thread.context, &kernel.address_space.arch, new_thread.kernel_stack.value, new_thread, &kernel.address_space);
}

pub const Thread = struct {
    privilege_level: PrivilegeLevel,
    type: Type,
    kernel_stack: Virtual.Address,
    kernel_stack_base: Virtual.Address,
    kernel_stack_size: u64,
    user_stack_base: Virtual.Address,
    user_stack_reserve: u64,
    user_stack_commit: u64,
    id: u64,
    context: *kernel.arch.Context,
    time_slices: u64,
    last_known_execution_address: u64,

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
        log.debug("Kernel stack: 0x{x}", .{kernel_stack.value});
        switch (privilege_level) {
            .kernel => {
                user_stack = kernel_stack;
            },
            .user => {
                TODO(@src());
            },
        }
        thread.privilege_level = privilege_level;
        thread.kernel_stack_base = kernel_stack;
        thread.kernel_stack_size = kernel_stack_size;
        thread.user_stack_base = switch (privilege_level) {
            .kernel => Virtual.Address.new(0),
            .user => user_stack,
        };
        thread.user_stack_reserve = user_stack_reserve;
        thread.user_stack_commit = user_stack_commit;
        thread.id = new_thread_id;
        thread.type = .normal;
        kernel.assert(@src(), thread.type == .normal);

        if (thread.type != .idle) {
            log.debug("Creating arch-specific thread initialization", .{});
            thread.context = kernel.arch.Context.new(thread, entry_point);
        }

        // TODO: thread queues
        log.debug("Thread created", .{});

        return thread;
    }

    pub fn terminate(thread: *Thread) void {
        _ = thread;
        TODO(@src());
    }
};

fn thread1(arg: u64) void {
    _ = arg;
    while (true) {
        log.debug("THREAD 1", .{});
        //log.debug("Interrupts enabled: {}", .{kernel.arch.are_interrupts_enabled()});
    }
}

fn thread2(arg: u64) void {
    _ = arg;
    while (true) {
        //log.debug("Interrupts enabled: {}", .{kernel.arch.are_interrupts_enabled()});
        log.debug("THREAD 2", .{});
    }
}

fn pick_thread() *Thread {
    const current_cpu = kernel.arch.get_current_cpu().?;
    const current_thread_id = if (current_cpu.current_thread) |current_thread| current_thread.id else 0;
    kernel.assert(@src(), current_thread_id <= 1);
    const current_thread_index = current_thread_id % thread_pool.len;
    const next_thread_index = @boolToInt(!(current_thread_index != 0));
    const new_thread = &thread_pool[next_thread_index];
    current_cpu.current_thread = new_thread;
    return new_thread;
}

pub fn init() void {
    _ = Thread.spawn(.kernel, Thread.EntryPoint{
        .start_address = @ptrToInt(thread1),
        .argument = 0,
    });
    _ = Thread.spawn(.kernel, Thread.EntryPoint{
        .start_address = @ptrToInt(thread2),
        .argument = 0,
    });
}
