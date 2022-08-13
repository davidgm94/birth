const Scheduler = @This();

const std = @import("../common/std.zig");

const Context = @import("arch/context.zig");
const CPU = @import("arch/common.zig").CPU;
const crash = @import("crash.zig");
const interrupts = @import("interrupts.zig");
const PhysicalAddressSpace = @import("physical_address_space.zig");
const PhysicalMemoryRegion = @import("physical_memory_region.zig");
const PrivilegeLevel = @import("scheduler_common.zig").PrivilegeLevel;
const Spinlock = @import("spinlock.zig");
const Thread = @import("thread.zig");
const TLS = @import("arch/tls.zig");
const VirtualAddress = @import("virtual_address.zig");
const VirtualAddressSpace = @import("virtual_address_space.zig");
const VAS = @import("arch/vas.zig");

const TODO = crash.TODO;
const log = std.log.scoped(.Scheduler);
const Allocator = std.Allocator;


lock: Spinlock,
thread_buffer: Thread.Buffer,
all_threads: Thread.List,
active_threads: Thread.List,
paused_threads: Thread.List,
cpus: []CPU,
initialized_ap_cpu_count: u64,

pub fn yield(scheduler: *Scheduler, old_context: *Context) void {
    log.debug("Yielding", .{});
    const current_cpu = TLS.get_current().cpu.?;
    if (current_cpu.spinlock_count > 0) {
        @panic("spins active when yielding");
    }
    interrupts.disable();
    scheduler.lock.acquire();
    var old_address_space: *VirtualAddressSpace = undefined;
    if (scheduler.lock.were_interrupts_enabled != 0) @panic("ffff");
    const old_thread = TLS.get_current();
    std.assert(@src(), old_thread.state == .active);
    old_thread.context = old_context;
    old_address_space = old_thread.address_space;
    const new_thread = scheduler.pick_thread();
    new_thread.cpu = old_thread.cpu;
    new_thread.time_slices += 1;
    old_thread.state = .paused;
    new_thread.state = .active;
    // TODO: idle
    //
    if (new_thread.context.cs == 0x4b) std.assert(@src(), new_thread.context.ss == 0x43 and new_thread.context.ds == 0x43);

    //log.debug("RSP: 0x{x}", .{context.rsp});
    //log.debug("Stack top: 0x{x}", .{new_thread.kernel_stack_base.value + new_thread.kernel_stack_size});
    //common.runtime_assert(@src(), context.rsp < new_thread.kernel_stack_base.value + new_thread.kernel_stack_size);

    //common.arch.next_timer(1);
    //log.debug("New thread address: 0x{x}", .{@ptrToInt(&new_thread)});
    //log.debug("New address space offset: 0x{x}", .{@ptrToInt(&new_thread) + @offsetOf(Thread, "address_space")});
    //log.debug("New thread address: 0x{x}", .{@intToPtr(*u64, @ptrToInt(&new_thread) + @offsetOf(Thread, "address_space")).*});
    interrupts.disable_all();
    VAS.switch_address_spaces_if_necessary(new_thread.address_space);

    if (scheduler.lock.were_interrupts_enabled != 0) {
        @panic("interrupts were enabled");
    }
    scheduler.lock.release();
    old_context.check(@src());
    TLS.set_current(new_thread);

    // TODO: checks
    //const new_thread = current_thread.time_slices == 1;

    // TODO: close reference or dettach address space
    _ = old_address_space;
    // TODO: set up last know instruction address

    const cpu = new_thread.cpu orelse @panic("CPU pointer is missing in the post-context switch routine");
    // TODO: this is only supposed to be called from an interrupt
    interrupts.end(cpu);
    if (interrupts.are_enabled()) @panic("interrupts enabled");
    if (cpu.spinlock_count > 0) @panic("spinlocks active");
    // TODO: profiling
    common.arch.legacy_actions_before_context_switch(new_thread);
    common.arch.set_new_stack(@ptrToInt(new_thread.context));
    common.arch.interrupts_epilogue();

    @panic("wtfffF");
}

const default_kernel_stack_size = 0x5000;
const default_kernel_stack_reserve = default_kernel_stack_size;
const default_user_stack_reserve = 0x400000;
const default_user_stack_commit = 0x10000;

const ThreadStack = struct {
    kernel: VirtualAddress,
    user: ?VirtualAddress,
};

pub fn bulk_spawn_same_thread(scheduler: *Scheduler, virtual_address_space: *VirtualAddressSpace, comptime privilege_level: PrivilegeLevel, thread_count: u64, entry_point: u64) []Thread {
    comptime {
        common.comptime_assert(privilege_level == .kernel);
    }

    const thread_stack_size = switch (privilege_level) {
        .kernel => default_kernel_stack_reserve,
        else => unreachable,
    };
    const thread_bulk_stack_allocation_size = thread_count * thread_stack_size;
    const thread_bulk_stack_allocation = virtual_address_space.allocate(thread_bulk_stack_allocation_size, null, .{ .write = true }) catch @panic("unable to allocate the kernel stack");

    const existing_threads = scheduler.all_threads.count;
    log.debug("Existing threads: {}", .{existing_threads});
    common.runtime_assert(@src(), existing_threads + thread_count <= Thread.Buffer.Bucket.size);
    common.runtime_assert(@src(), scheduler.thread_buffer.element_count == scheduler.all_threads.count);
    const bucket_count = scheduler.thread_buffer.bucket_count;
    common.runtime_assert(@src(), bucket_count == 1);
    var thread_i: u64 = 0;
    while (thread_i < thread_count) : (thread_i += 1) {
        const stack_allocation_offset = thread_i * thread_stack_size;
        const thread_stack = ThreadStack{
            .kernel = thread_bulk_stack_allocation.offset(stack_allocation_offset),
            .user = null,
        };
        _ = scheduler.spawn_thread(virtual_address_space, virtual_address_space, privilege_level, entry_point, thread_stack, null);
    }

    return scheduler.thread_buffer.first.?.data[existing_threads .. existing_threads + thread_count];
}

pub fn spawn_thread(scheduler: *Scheduler, kernel_virtual_address_space: *VirtualAddressSpace, thread_virtual_address_space: *VirtualAddressSpace, comptime privilege_level: PrivilegeLevel, entry_point: u64, maybe_thread_stack: ?ThreadStack, cpu: ?*CPU) *Thread {
    if (maybe_thread_stack != null) {
        common.runtime_assert(@src(), privilege_level == .kernel);
    }

    // TODO: lock
    const new_thread_id = scheduler.thread_buffer.element_count;
    log.debug("About to allocate 1", .{});
    const thread = scheduler.thread_buffer.add_one(kernel_virtual_address_space.heap.allocator) catch @panic("thread buffer");
    scheduler.all_threads.append(&thread.all_item, thread) catch @panic("wtf");
    log.debug("Ended to allocate", .{});

    // TODO: should we always use the same address space for kernel tasks?
    thread.address_space = thread_virtual_address_space;

    var kernel_stack_size: u64 = 0x5000;
    const user_stack_reserve: u64 = switch (privilege_level) {
        .kernel => default_kernel_stack_reserve,
        .user => default_user_stack_reserve,
    };
    const user_stack_commit: u64 = switch (privilege_level) {
        .kernel => 0,
        .user => default_user_stack_commit,
    };
    // TODO: implemented idle thread

    // TODO: should this be kernel virtual address space?
    // TODO: this may crash
    const kernel_stack = blk: {
        if (maybe_thread_stack) |thread_stack|
            break :blk thread_stack.kernel
        else {
            log.debug("About to allocate 2", .{});
            const result = thread_virtual_address_space.allocate(kernel_stack_size, null, .{ .write = true }) catch @panic("unable to allocate the kernel stack");
            log.debug("Ended to allocate", .{});
            break :blk result;
        }
    };
    common.runtime_assert(@src(), kernel_stack.is_higher_half());
    const user_stack = switch (privilege_level) {
        .kernel => kernel_stack,
        .user => blk: {
            // TODO: lock
            common.runtime_assert(@src(), common.is_aligned(user_stack_reserve, context.page_size));
            if (maybe_thread_stack) |thread_stack|
                break :blk thread_stack.user orelse @panic("Wtffffff")
            else {
                log.debug("About to allocate 3", .{});
                const result = thread_virtual_address_space.allocate(user_stack_reserve, null, .{ .write = true, .user = true }) catch @panic("user stack");
                log.debug("Ended to allocate", .{});
                break :blk result;
            }
        },
    };
    thread.privilege_level = privilege_level;
    log.debug("Thread privilege: {}", .{thread.privilege_level});
    thread.kernel_stack_base = kernel_stack;
    thread.kernel_stack_size = kernel_stack_size;
    thread.user_stack_base = switch (privilege_level) {
        .kernel => VirtualAddress.invalid(),
        .user => user_stack,
    };
    log.debug("User stack address: 0x{x}", .{thread.user_stack_base.value});
    thread.user_stack_reserve = user_stack_reserve;
    thread.user_stack_commit = user_stack_commit;
    thread.id = new_thread_id;
    thread.type = .normal;
    common.runtime_assert(@src(), thread.type == .normal);
    thread.cpu = cpu;
    thread.state = .active;
    thread.executing = false;

    // TODO: don't hardcode this
    const syscall_queue_entry_count = 256;
    thread.syscall_manager = switch (privilege_level) {
        .user => common.Syscall.Manager.for_kernel(thread.address_space, syscall_queue_entry_count),
        .kernel => .{ .kernel = null, .user = null },
    };

    if (thread.type != .idle) {
        log.debug("Creating arch-specific thread initialization", .{});
        // TODO: hack
        thread.context = common.arch.Context.new(thread, entry_point);
    }

    scheduler.active_threads.append(&thread.queue_item, thread) catch @panic("wtf");

    return thread;
}

pub fn load_executable(scheduler: *Scheduler, kernel_address_space: *VirtualAddressSpace, comptime privilege_level: PrivilegeLevel, physical_address_space: *PhysicalAddressSpace, drive: *drivers.Filesystem, executable_filename: []const u8) *Thread {
    common.runtime_assert(@src(), kernel_address_space.privilege_level == .kernel);
    common.runtime_assert(@src(), privilege_level == .user);
    const executable_file = drive.read_file(drive, kernel_address_space.heap.allocator, @ptrToInt(kernel_address_space), executable_filename);
    const user_virtual_address_space = kernel_address_space.heap.allocator.create(VirtualAddressSpace) catch @panic("wtf");
    VirtualAddressSpace.initialize_user_address_space(user_virtual_address_space, physical_address_space, kernel_address_space) orelse @panic("wtf2");
    const elf_result = common.ELF.parse(.{ .user = user_virtual_address_space, .kernel = kernel_address_space, .physical = physical_address_space }, executable_file);
    //common.runtime_assert(@src(), elf_result.entry_point == 0x200110);
    const thread = scheduler.spawn_thread(kernel_address_space, user_virtual_address_space, privilege_level, elf_result.entry_point, null, null);

    return thread;
}

pub fn terminate(thread: *Thread) void {
    _ = thread;
    TODO(@src());
}

fn pick_thread(scheduler: *Scheduler) *Thread {
    log.debug("Scheduler active threads: {}", .{scheduler.active_threads.count});
    log.debug("Scheduler paused threads: {}", .{scheduler.paused_threads.count});
    var maybe_active_thread_node = scheduler.active_threads.first;
    while (maybe_active_thread_node) |active_thread_node| : (active_thread_node = active_thread_node.next) {
        const active_thread = active_thread_node.data;
        scheduler.active_threads.remove(active_thread_node);
        return active_thread;
    }

    @panic("Nothing to schedule");
}
