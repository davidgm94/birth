const Scheduler = @This();

const std = @import("../common/std.zig");

const arch = @import("arch/common.zig");
const Context = arch.Context;
const context_switch = @import("arch/context_switch.zig");
const CPU = arch.CPU;
const crash = @import("crash.zig");
const ELF = @import("elf.zig");
const Filesystem = @import("../drivers/filesystem.zig");
const interrupts = @import("arch/interrupts.zig");
const PhysicalAddressSpace = @import("physical_address_space.zig");
const PhysicalMemoryRegion = @import("physical_memory_region.zig");
const PrivilegeLevel = @import("scheduler_common.zig").PrivilegeLevel;
const Spinlock = @import("spinlock.zig");
const Syscall = @import("syscall.zig");
const Thread = @import("thread.zig");
const TLS = @import("arch/tls.zig");
const VirtualAddress = @import("virtual_address.zig");
const VirtualAddressSpace = @import("virtual_address_space.zig");
const VAS = arch.VAS;

const TODO = crash.TODO;
const log = std.log.scoped(.Scheduler);
const Allocator = std.Allocator;

lock: Spinlock,
thread_buffer: Thread.Buffer,
all_threads: Thread.List,
active_threads: Thread.List,
paused_threads: Thread.List,
cpus: []CPU,
current_threads: []*Thread,
initialized_ap_cpu_count: u64,

var yield_times: u64 = 0;

pub fn yield(scheduler: *Scheduler, old_context: *Context) void {
    yield_times += 1;
    if (yield_times == 3) @panic("STOP");
    log.debug("Yielding", .{});
    const current_cpu = TLS.get_current().cpu.?;
    if (current_cpu.spinlock_count > 0) {
        @panic("spins active when yielding");
    }
    interrupts.disable();
    log.debug("Acquiring scheduler lock", .{});
    scheduler.lock.acquire();
    log.debug("Scheduler lock acquired", .{});
    var old_address_space: *VirtualAddressSpace = undefined;
    if (scheduler.lock.were_interrupts_enabled != 0) @panic("ffff");
    const old_thread = TLS.get_current();
    std.assert(old_thread.state == .active);
    old_thread.context = old_context;
    old_address_space = old_thread.address_space;
    const new_thread = scheduler.pick_thread(current_cpu);
    new_thread.time_slices += 1;
    old_thread.state = .paused;
    new_thread.state = .active;
    if (new_thread.context.cs == 0x4b) std.assert(new_thread.context.ss == 0x43 and new_thread.context.ds == 0x43);

    interrupts.disable_all();
    log.debug("New thread address space: 0x{x}", .{@ptrToInt(new_thread.address_space)});
    VAS.switch_address_spaces_if_necessary(new_thread.address_space);

    if (scheduler.lock.were_interrupts_enabled != 0) {
        @panic("interrupts were enabled");
    }
    //old_context.check(@src());
    TLS.set_current(scheduler, new_thread, old_thread.cpu.?);
    scheduler.lock.release();

    // TODO: checks
    //const new_thread = current_thread.time_slices == 1;

    // TODO: close reference or dettach address space
    _ = old_address_space;
    // TODO: set up last know instruction address

    const cpu = new_thread.cpu orelse @panic("CPU pointer is missing in the post-context switch routine");
    // TODO: this is only supposed to be called from an interrupt
    log.debug("LAPIC EOI start", .{});
    interrupts.end(cpu);
    log.debug("LAPIC EOI end", .{});
    if (interrupts.are_enabled()) @panic("interrupts enabled");
    if (cpu.spinlock_count > 0) @panic("spinlocks active");
    // TODO: profiling
    context_switch.swap_privilege_registers(new_thread);
    context_switch.set_new_kernel_stack(new_thread);
    context_switch.set_new_stack(@ptrToInt(new_thread.context));
    context_switch.epilogue();

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

pub const ThreadEntryPoint = struct {
    address: u64,
    arguments: [6]u64 = [1]u64{0} ** 6,
};

// TODO: take into account parameters
// TODO: take into account thread type
pub fn spawn_kernel_thread(scheduler: *Scheduler, kernel_address_space: *VirtualAddressSpace, thread_entry_point: ThreadEntryPoint) ?*Thread {
    return scheduler.spawn_thread(kernel_address_space, kernel_address_space, .kernel, .normal, thread_entry_point.address, null, null);
}

pub fn load_executable(scheduler: *Scheduler, kernel_address_space: *VirtualAddressSpace, privilege_level: PrivilegeLevel, physical_address_space: *PhysicalAddressSpace, drive: *Filesystem, executable_filename: []const u8) *Thread {
    std.assert(kernel_address_space.privilege_level == .kernel);
    std.assert(privilege_level == .user);
    const executable_file = drive.read_file(drive, kernel_address_space.heap.allocator, @ptrToInt(kernel_address_space), executable_filename);
    const user_virtual_address_space = kernel_address_space.heap.allocator.create(VirtualAddressSpace) catch @panic("wtf");
    VirtualAddressSpace.initialize_user_address_space(user_virtual_address_space, physical_address_space, kernel_address_space) orelse @panic("wtf2");
    const elf_result = ELF.parse(.{ .user = user_virtual_address_space, .kernel = kernel_address_space, .physical = physical_address_space }, executable_file);
    //std.assert(elf_result.entry_point == 0x200110);
    const thread = scheduler.spawn_thread(kernel_address_space, user_virtual_address_space, privilege_level, elf_result.entry_point, null, null);

    return thread;
}

pub fn terminate(thread: *Thread) void {
    _ = thread;
    TODO(@src());
}

fn pick_thread(scheduler: *Scheduler, cpu: *CPU) *Thread {
    scheduler.lock.assert_locked();
    log.debug("Scheduler active threads: {}", .{scheduler.active_threads.count});
    log.debug("Scheduler paused threads: {}", .{scheduler.paused_threads.count});

    var maybe_active_thread_node = scheduler.active_threads.first;

    while (maybe_active_thread_node) |active_thread_node| : (active_thread_node = active_thread_node.next) {
        const active_thread = active_thread_node.data;
        scheduler.active_threads.remove(active_thread_node);
        return active_thread;
    }

    return cpu.idle_thread;
}

pub fn bootstrap_cpus(scheduler: *Scheduler, virtual_address_space: *VirtualAddressSpace, entry_point: u64, cpu_count: u64) void {
    scheduler.lock.acquire();
    //const bsp_thread = TLS.get_current();
    //const bsp_cpu = bsp_thread.cpu orelse @panic("cpu");
    const threads = scheduler.thread_buffer.add_many(virtual_address_space.heap.allocator, cpu_count) catch @panic("wtf");
    scheduler.current_threads = virtual_address_space.heap.allocator.alloc(*Thread, threads.len) catch @panic("wtf");
    const thread_stack_size = default_kernel_stack_reserve;
    const thread_bulk_stack_allocation_size = threads.len * thread_stack_size;
    _ = thread_bulk_stack_allocation_size;
    const thread_stacks = virtual_address_space.allocate(thread_bulk_stack_allocation_size, null, .{ .write = true }) catch @panic("wtF");

    for (threads) |*thread, thread_i| {
        scheduler.current_threads[thread_i] = thread;

        const stack_allocation_offset = thread_i * thread_stack_size;
        const thread_stack = ThreadStack{
            .kernel = thread_stacks.offset(stack_allocation_offset),
            .user = null,
        };
        //pub fn initialize_thread(scheduler: *Scheduler, thread: *Thread, thread_id: u64, thread_virtual_address_space: *VirtualAddressSpace, privilege_level: PrivilegeLevel, thread_type: Thread.Type, entry_point: u64, thread_stack: ThreadStack, cpu: ?*CPU) *Thread {
        scheduler.initialize_thread(thread, thread_i, virtual_address_space, .kernel, .idle, entry_point, thread_stack);
        thread.cpu = &scheduler.cpus[thread_i];
    }

    // Update bsp CPU
    TLS.preset(scheduler, &scheduler.cpus[0]);
    TLS.set_current(scheduler, &scheduler.cpus[0]);
    // threads[0].context = bsp_cpu.context;

    scheduler.lock.release();

    @panic("TODO bootstrap cpus");

    //scheduler.cpus[0] = bootstrap_context.cpu;
    //scheduler.cpus[0].is_bootstrap = true;
    //const bsp_thread = scheduler.thread_buffer.add_one(virtual_address_space.heap.allocator) catch @panic("wtf");
    //scheduler.all_threads.append(&bsp_thread.all_item, bsp_thread) catch @panic("wtF");
    //bsp_thread.context = &bootstrap_context.context;
    //bsp_thread.state = .active;
    //bsp_thread.cpu = &scheduler.cpus[0];
    //bsp_thread.address_space = virtual_address_space;
    //TLS.set_current(bsp_thread);
    //// @Allocation
    //const cpu_count = scheduler.cpus.len;
    //const bsp_thread = tls_pointers[0];
    //std.assert(bsp_thread.cpu.?.is_bootstrap);
    //tls_pointers = virtual_address_space.heap.allocator.alloc(*Thread, cpu_count) catch @panic("wtf");
    //std.assert(tls_pointers[0] == bsp_thread);
    //TLS.allocate_and_setup(virtual_address_space, scheduler);

    //const entry_point = @ptrToInt(smp_entry);
    //const ap_cpu_count = scheduler.cpus.len - 1;
    //var ap_threads: []Thread = &.{};
    //if (ap_cpu_count > 0) {
    //// @Allocation
    //ap_threads = scheduler.bulk_spawn_same_thread(virtual_address_space, .kernel, ap_cpu_count, entry_point);
    //std.assert(scheduler.all_threads.count == ap_threads.len + 1);
    //std.assert(scheduler.all_threads.count < Thread.Buffer.Bucket.size);
    //}

    //const all_threads = scheduler.thread_buffer.first.?.data[0..thread_count];
    //std.assert(&all_threads[0] == bsp_thread);

    //for (smps) |smp, index| {
    //const cpu = &scheduler.cpus[index];
    //const thread = &all_threads[index];
    //cpu.lapic.id = smp.lapic_id;
    //cpu.idle_thread = thread;
    //cpu.id = smp.processor_id;
    //thread.cpu = cpu;
    //thread.executing = true;
    //}

    //// TODO: don't hardcode stack size
    //// @Allocation
    //CPU.bootstrap_stacks(scheduler.cpus, virtual_address_space, 0x10000);
    //std.assert(std.cpu.arch == .x86_64);
    //scheduler.cpus[0].map_lapic(virtual_address_space);

    //if (ap_cpu_count > 0) {
    //scheduler.lock.acquire();
    //for (smps[1..]) |*smp, index| {
    //const ap_thread = &ap_threads[index];
    //scheduler.active_threads.remove(&ap_thread.queue_item);
    //const stack_pointer = ap_thread.context.get_stack_pointer();
    //smp.extra_argument = @ptrToInt(&cpu_initialization_context);
    //smp.target_stack = stack_pointer;
    //smp.goto_address = entry_point;
    //}

    //std.assert(scheduler.active_threads.count == 0);
    //scheduler.lock.release();
    //}
}

pub fn spawn_thread(scheduler: *Scheduler, kernel_virtual_address_space: *VirtualAddressSpace, thread_virtual_address_space: *VirtualAddressSpace, privilege_level: PrivilegeLevel, thread_type: Thread.Type, entry_point: u64, maybe_thread_stack: ?ThreadStack, cpu: ?*CPU) *Thread {
    if (maybe_thread_stack != null) {
        std.assert(privilege_level == .kernel);
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
    std.assert(kernel_stack.is_higher_half());
    const user_stack = switch (privilege_level) {
        .kernel => kernel_stack,
        .user => blk: {
            // TODO: lock
            std.assert(std.is_aligned(user_stack_reserve, arch.page_size));
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
    thread.type = thread_type;
    thread.cpu = cpu;
    thread.state = .active;
    thread.executing = false;

    // TODO: don't hardcode this
    const syscall_queue_entry_count = 256;
    thread.syscall_manager = switch (privilege_level) {
        .user => Syscall.KernelManager.new(thread.address_space, syscall_queue_entry_count),
        .kernel => .{ .kernel = null, .user = null },
    };

    if (thread.type != .idle) {
        log.debug("Creating arch-specific thread initialization", .{});
        // TODO: hack
        thread.context = Context.new(thread, entry_point);
    }

    scheduler.active_threads.append(&thread.queue_item, thread) catch @panic("wtf");

    return thread;
}

pub fn initialize_thread(scheduler: *Scheduler, thread: *Thread, thread_id: u64, thread_virtual_address_space: *VirtualAddressSpace, privilege_level: PrivilegeLevel, thread_type: Thread.Type, entry_point: u64, thread_stack: ThreadStack) void {
    scheduler.lock.assert_locked();
    thread.all_item = Thread.ListItem.new(thread);
    thread.queue_item = Thread.ListItem.new(thread);
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
    const kernel_stack = thread_stack.kernel;
    std.assert(kernel_stack.is_higher_half());
    const user_stack = switch (privilege_level) {
        .kernel => kernel_stack,
        .user => blk: {
            // TODO: lock
            std.assert(std.is_aligned(user_stack_reserve, arch.page_size));
            break :blk thread_stack.user orelse @panic("Wtffffff");
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
    thread.id = thread_id;
    thread.type = thread_type;
    thread.cpu = null;
    thread.state = .active;
    thread.executing = false;

    // TODO: don't hardcode this
    const syscall_queue_entry_count = 256;
    thread.syscall_manager = switch (privilege_level) {
        .user => Syscall.KernelManager.new(thread.address_space, syscall_queue_entry_count),
        .kernel => .{ .kernel = null, .user = null },
    };

    if (thread.type != .idle) {
        log.debug("Creating arch-specific thread initialization", .{});
        // TODO: hack
        thread.context = Context.new(thread, entry_point);
    }

    scheduler.active_threads.append(&thread.queue_item, thread) catch @panic("wtf");
}
