const lib = @import("lib");
const log = lib.log.scoped(.thread);
const user = @import("user");
const rise = @import("rise");

const VirtualAddress = user.VirtualAddress;

pub const Thread = extern struct {
    self: *Thread,
    previous: ?*Thread,
    next: ?*Thread,
    stack: [*]u8,
    stack_top: [*]align(lib.arch.stack_alignment) u8,
    register_arena: rise.arch.RegisterArena align(lib.arch.stack_alignment),
    core_id: u32,

    pub fn init(thread: *Thread, scheduler: *user.arch.Scheduler) void {
        thread.self = thread;
        thread.previous = null;
        thread.next = null;
        thread.core_id = scheduler.generic.core_id;
    }
};

pub const Mutex = extern struct {
    locked: bool = false,

    pub inline fn internalLock(mutex: *volatile Mutex) void {
        mutex.locked = true;
    }
};

var static_stack: [0x10000]u8 align(lib.arch.stack_alignment) = undefined;
var static_thread: Thread = undefined;
var static_thread_lock = Mutex{};

pub fn initDisabled(scheduler: *user.arch.Scheduler) noreturn {
    const thread = &static_thread;
    static_thread_lock.internalLock();
    thread.stack = &static_stack;
    thread.stack_top = static_stack[static_stack.len..];
    thread.init(scheduler);

    // TODO: use RAX as parameter?

    user.arch.setInitialState(&thread.register_arena, VirtualAddress.new(bootstrapThread), VirtualAddress.new(thread.stack_top), .{0} ** 6);

    scheduler.common.generic.has_work = true;

    scheduler.restore(&thread.register_arena);
}

fn bootstrapThread(parameters: ?*anyopaque) callconv(.C) noreturn {
    // TODO: Implement libc glue code
    // TODO: Implement rise glue code
    if (user.is_init) {
        // No allocation path
        mainThread(parameters);
    } else {
        // Do allocations
        while (true) {}
    }
}

fn mainThread(parameters: ?*anyopaque) noreturn {
    // TODO: parameters
    _ = parameters;
    const root = @import("root");
    if (@hasDecl(root, "main")) {
        const result = switch (@typeInfo(@typeInfo(@TypeOf(root.main)).Fn.return_type.?)) {
            .NoReturn => root.main(),
            .Void => blk: {
                root.main();
                break :blk 0;
            },
            .Int => root.main(),
            .ErrorUnion => blk: {
                const result = root.main() catch {
                    // TODO: log
                    break :blk 1;
                };

                switch (@typeInfo(@TypeOf(result))) {
                    .Void => break :blk 0,
                    .Int => break :blk result,
                    else => @compileError("Unexpected return type"),
                }
            },
            else => @compileError("Unexpected return type"),
        };
        _ = result;
        @panic("ASdasd");
    } else {
        const result = _main();
        _ = result;
    }
}

export fn _main() i32 {
    // global constructors
    // array
    return 0;
}
