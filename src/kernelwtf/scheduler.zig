const Scheduler = @This();

const common = @import("common");
const assert = common.assert;

const rise = @import("rise");
const ELF = rise.ELF;
const Filesystem = rise.Filesystem;
const PhysicalAddress = rise.PhysicalAddress;
const PhysicalAddressSpace = rise.PhysicalAddressSpace;
const PrivilegeLevel = rise.PrivilegeLevel;
const Process = rise.Process;
const Spinlock = rise.Spinlock;
const Syscall = rise.Syscall;
const Thread = rise.Thread;
const TODO = rise.TODO;
const VirtualAddress = rise.VirtualAddress;
const VirtualAddressSpace = rise.VirtualAddressSpace;
const VirtualMemoryRegion = rise.VirtualMemoryRegion;

const kernel = @import("kernel");

const arch = @import("arch");
const Context = arch.Context;
const context_switch = arch.context_switch;
const CPU = arch.CPU;
const interrupts = arch.interrupts;
const TLS = arch.TLS;
const VAS = arch.VAS;

lock: Spinlock,
all_threads: Thread.List,
active_threads: Thread.List,
paused_threads: Thread.List,

pub fn yield(scheduler: *Scheduler, old_context: *Context) void {
    // TODO @Warning @Error We are not supposed to log in performance-sensitive context
    const log = common.log.scoped(.Yield);
    const current_thread = TLS.get_current();
    const current_cpu = current_thread.cpu.?;
    if (current_cpu.spinlock_count > 0) {
        @panic("spins active when yielding");
    }
    interrupts.disable();
    scheduler.lock.acquire();
    log.debug("Current thread: #{}", .{current_thread.id});
    if (scheduler.lock.were_interrupts_enabled != 0) @panic("ffff");
    log.debug("Thread state: {}", .{current_thread.state});
    assert(current_thread.state == .active);
    current_thread.context = old_context;
    if (current_thread.state == .active and current_thread.type != .idle) {
        scheduler.active_threads.append(&current_thread.queue_item, current_thread) catch @panic("Wtf");
    }
    const new_thread = scheduler.pick_thread(current_cpu);
    new_thread.time_slices += 1;
    //current_thread.state = .paused;
    new_thread.state = .active;
    if (new_thread.get_context().cs == 0x4b) assert(new_thread.get_context().ss == 0x43 and new_thread.get_context().ds == 0x43);

    interrupts.disable_all();
    VAS.switch_address_spaces_if_necessary(new_thread.process.virtual_address_space);

    if (scheduler.lock.were_interrupts_enabled != 0) {
        @panic("interrupts were enabled");
    }
    //old_context.check(@src());
    TLS.set_current(new_thread, current_cpu);
    scheduler.lock.release();

    // TODO: checks
    //const new_thread = current_thread.time_slices == 1;

    // TODO: close reference or dettach address space
    // TODO: set up last know instruction address

    // TODO: this is only supposed to be called from an interrupt
    interrupts.end(current_cpu);
    if (interrupts.are_enabled()) @panic("interrupts enabled");
    if (@as(*volatile u64, &current_cpu.spinlock_count).* > 0) @panic("spinlocks active");
    // TODO: profiling
    context_switch.swap_privilege_registers(new_thread);
    context_switch.set_new_kernel_stack(new_thread);
    context_switch.set_new_stack(@ptrToInt(new_thread.context));
    context_switch.epilogue();

    @panic("wtfffF");
}

pub const default_kernel_stack_size = 0x5000;
const default_user_stack_size = 0x400000;

pub const ThreadStack = struct {
    kernel: VirtualMemoryRegion,
    user: VirtualMemoryRegion,
};

pub const ThreadEntryPoint = struct {
    address: u64,
    arguments: [6]u64 = [1]u64{0} ** 6,
};

// TODO: take into account parameters
// TODO: take into account thread type
pub fn spawn_kernel_thread(scheduler: *Scheduler, thread_entry_point: ThreadEntryPoint) !*Thread {
    return scheduler.spawn_thread(.kernel, thread_entry_point.address, kernel.process);
}

pub fn terminate(thread: *Thread) void {
    _ = thread;
    TODO(@src());
}

fn pick_thread(scheduler: *Scheduler, cpu: *CPU) *Thread {
    scheduler.lock.assert_locked();

    var maybe_active_thread_node = scheduler.active_threads.first;

    while (maybe_active_thread_node) |active_thread_node| : (active_thread_node = active_thread_node.next) {
        const active_thread = active_thread_node.data;
        scheduler.active_threads.remove(active_thread_node);
        return active_thread;
    }

    if (true) @panic("wtf");

    return cpu.idle_thread;
}

pub fn spawn_thread(scheduler: *Scheduler, privilege_level: PrivilegeLevel, entry_point: u64, parent_process: *Process) !*Thread {
    //const log = common.log.scoped(.SpawnThread);
    scheduler.lock.acquire();
    defer {
        scheduler.lock.release();
    }

    // @ZigBug We have take a pointer here because otherwise it copies the whole struct and kernel crashes
    const memory = &kernel.memory;
    const thread_id = memory.threads.len;
    const thread = kernel.memory.threads.add_one(kernel.virtual_address_space.heap.allocator) catch @panic("thread buffer");

    const kernel_stack_size = default_kernel_stack_size;
    const kernel_stack = kernel.virtual_address_space.allocate(kernel_stack_size, null, .{ .write = true }) catch @panic("unable to allocate the kernel stack");
    const thread_stack = switch (privilege_level) {
        .kernel => ThreadStack{
            .kernel = .{ .address = kernel_stack, .size = kernel_stack_size },
            .user = .{ .address = kernel_stack, .size = kernel_stack_size },
        },
        .user => blk: {
            const user_stack_size = default_user_stack_size;
            assert(common.is_aligned(user_stack_size, arch.page_size));
            const user_stack = parent_process.virtual_address_space.allocate(user_stack_size, null, .{ .write = true, .user = true }) catch @panic("user stack");
            break :blk ThreadStack{
                .kernel = .{ .address = kernel_stack, .size = kernel_stack_size },
                .user = .{ .address = user_stack, .size = user_stack_size },
            };
        },
    };

    scheduler.initialize_thread(thread, thread_id, privilege_level, .normal, entry_point, thread_stack, parent_process);

    common.log.scoped(.SpawnThread).debug("Spawning thread with id #{}", .{thread_id});

    return thread;
}

/// Can't log inside this function, early initialization migh crash
pub fn initialize_thread(scheduler: *Scheduler, thread: *Thread, thread_id: u64, privilege_level: PrivilegeLevel, thread_type: Thread.Type, entry_point: u64, thread_stack: ThreadStack, parent_process: *Process) void {
    scheduler.lock.assert_locked();

    thread.* = Thread{
        .all_item = Thread.ListItem.new(thread),
        .queue_item = Thread.ListItem.new(thread),
        .privilege_level = privilege_level,
        .id = thread_id,
        .type = thread_type,
        .cpu = null,
        .state = .active,
        .executing = false,
        .time_slices = 0,
        .process = parent_process,
        .message_queue = .{},
        // Defined in Context initialization
        .kernel_stack = VirtualAddress.invalid(),
        .kernel_stack_base = thread_stack.kernel.address,
        .kernel_stack_size = thread_stack.kernel.size,
        .user_stack_base = thread_stack.user.address,
        .user_stack_size = thread_stack.user.size,
        // Defined below
        .context = undefined,
        // Defined below for normal threads
        .syscall_manager = undefined,
    };

    thread.context = Context.new(thread, entry_point);

    scheduler.all_threads.append(&thread.all_item, thread) catch @panic("wtf");

    if (thread.type == .normal) {
        // TODO: don't hardcode this
        const syscall_queue_entry_count = 256;
        thread.syscall_manager = switch (privilege_level) {
            .user => Syscall.KernelManager.new(thread.process.virtual_address_space, syscall_queue_entry_count),
            .kernel => .{ .kernel = null, .user = null },
        };

        scheduler.active_threads.append(&thread.queue_item, thread) catch @panic("wtf");
    }
}
