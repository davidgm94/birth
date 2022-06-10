const kernel = @import("kernel.zig");
const TODO = kernel.TODO;
const log = kernel.log.scoped(.Scheduler);

pub const Context = kernel.arch.Context;

const Process = struct {
    thread: Context,
    lock: kernel.Spinlock,
    pid: u64,
    state: State,

    const State = enum {
        unused,
        used,
        sleeping,
        runnable,
        running,
        zombie,
    };
};

var _processes_array: [64]Process = undefined;
var processes: []Process = undefined;

pub fn schedule() noreturn {
    // TODO: move away this
    create_new_process(@ptrToInt(new_fn));
    const local_storage = kernel.arch.LocalStorage.get();
    log.debug("Local storage pid: {}", .{local_storage.context.pid});
    local_storage.context.pid = kernel.maxInt(u64);

    while (true) {
        kernel.arch.enable_interrupts();

        for (processes) |*process| {
            process.lock.acquire();
            if (process.state == .runnable) {
                process.state = .running;
                local_storage.context.pid = process.pid;

                var local_context: Context = undefined;
                kernel.arch.switch_context(&local_context, &process.thread);

                process.pid = kernel.maxInt(u64);
            }

            process.lock.release();
        }
    }
}

pub fn new_fn() noreturn {
    while (true) {
        log.debug("new process", .{});
    }
}

pub fn create_new_process(entry_point: u64) void {
    // TODO:
    processes = _processes_array[0..2];
    processes[0].state = .running;
    var new_process = &processes[1];
    new_process.state = .runnable;
    // TODO:
    new_process.thread.sp = kernel.arch.get_indexed_stack(1);
    log.debug("created new process", .{});
    new_process.thread.ra = entry_point;
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
