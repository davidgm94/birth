const Scheduler = @This();

const common = @import("common");
const assert = common.assert;

const RNU = @import("RNU");
const ELF = RNU.ELF;
const Filesystem = RNU.Filesystem;
const PhysicalAddress = RNU.PhysicalAddress;
const PhysicalAddressSpace = RNU.PhysicalAddressSpace;
const PrivilegeLevel = RNU.PrivilegeLevel;
const Spinlock = RNU.Spinlock;
const Syscall = RNU.Syscall;
const Thread = RNU.Thread;
const TODO = RNU.TODO;
const VirtualAddress = RNU.VirtualAddress;
const VirtualAddressSpace = RNU.VirtualAddressSpace;
const VirtualMemoryRegion = RNU.VirtualMemoryRegion;

const kernel = @import("kernel");

const arch = @import("arch");
const Context = arch.Context;
const context_switch = arch.context_switch;
const CPU = arch.CPU;
const interrupts = arch.interrupts;
const TLS = arch.TLS;
const VAS = arch.VAS;

lock: Spinlock,
thread_buffer: Thread.Buffer,
all_threads: Thread.List,
active_threads: Thread.List,
paused_threads: Thread.List,
cpus: []CPU,
current_threads: []*Thread,
initialized_ap_cpu_count: u64,

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
    var old_address_space: *VirtualAddressSpace = undefined;
    if (scheduler.lock.were_interrupts_enabled != 0) @panic("ffff");
    assert(current_thread.state == .active);
    current_thread.context = old_context;
    old_address_space = current_thread.address_space;
    if (current_thread.state == .active and current_thread.type != .idle) {
        scheduler.active_threads.append(&current_thread.queue_item, current_thread) catch @panic("Wtf");
    }
    const new_thread = scheduler.pick_thread(current_cpu);
    new_thread.time_slices += 1;
    //current_thread.state = .paused;
    new_thread.state = .active;
    if (new_thread.context.cs == 0x4b) assert(new_thread.context.ss == 0x43 and new_thread.context.ds == 0x43);

    interrupts.disable_all();
    VAS.switch_address_spaces_if_necessary(new_thread.address_space);

    if (scheduler.lock.were_interrupts_enabled != 0) {
        @panic("interrupts were enabled");
    }
    //old_context.check(@src());
    TLS.set_current(scheduler, new_thread, current_cpu);
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
pub fn spawn_kernel_thread(scheduler: *Scheduler, kernel_address_space: *VirtualAddressSpace, thread_entry_point: ThreadEntryPoint) ?*Thread {
    return scheduler.spawn_thread(kernel_address_space, kernel_address_space, .kernel, thread_entry_point.address);
}

pub fn load_executable(scheduler: *Scheduler, kernel_address_space: *VirtualAddressSpace, privilege_level: PrivilegeLevel, physical_address_space: *PhysicalAddressSpace, drive: *Filesystem, executable_filename: []const u8) !*Thread {
    assert(kernel_address_space.privilege_level == .kernel);
    assert(privilege_level == .user);
    const executable_file = try drive.read_file(kernel_address_space.heap.allocator, executable_filename, null);
    const user_virtual_address_space = kernel_address_space.heap.allocator.create(VirtualAddressSpace) catch @panic("wtf");
    VirtualAddressSpace.initialize_user_address_space(user_virtual_address_space);
    const elf_result = ELF.load(.{ .user = user_virtual_address_space, .kernel = kernel_address_space, .physical = physical_address_space }, executable_file);
    const thread = scheduler.spawn_thread(kernel_address_space, user_virtual_address_space, privilege_level, elf_result.entry_point);

    return thread;
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

pub fn spawn_thread(scheduler: *Scheduler, kernel_virtual_address_space: *VirtualAddressSpace, thread_virtual_address_space: *VirtualAddressSpace, privilege_level: PrivilegeLevel, entry_point: u64) *Thread {
    scheduler.lock.acquire();
    defer {
        scheduler.lock.release();
    }

    const thread_id = scheduler.thread_buffer.element_count;
    const thread = scheduler.thread_buffer.add_one(kernel_virtual_address_space.heap.allocator) catch @panic("thread buffer");

    const kernel_stack_size = default_kernel_stack_size;
    const kernel_stack = thread_virtual_address_space.allocate(kernel_stack_size, null, .{ .write = true }) catch @panic("unable to allocate the kernel stack");
    const thread_stack = switch (privilege_level) {
        .kernel => ThreadStack{
            .kernel = .{ .address = kernel_stack, .size = kernel_stack_size },
            .user = .{ .address = kernel_stack, .size = kernel_stack_size },
        },
        .user => blk: {
            const user_stack_size = default_user_stack_size;
            assert(common.is_aligned(user_stack_size, arch.page_size));
            const user_stack = thread_virtual_address_space.allocate(user_stack_size, null, .{ .write = true, .user = true }) catch @panic("user stack");
            break :blk ThreadStack{
                .kernel = .{ .address = kernel_stack, .size = kernel_stack_size },
                .user = .{ .address = user_stack, .size = user_stack_size },
            };
        },
    };

    scheduler.initialize_thread(thread, thread_id, thread_virtual_address_space, privilege_level, .normal, entry_point, thread_stack);

    common.log.scoped(.SpawnThread).debug("Spawning thread with id #{}", .{thread_id});

    return thread;
}

/// Can't log inside this function, early initialization migh crash
pub fn initialize_thread(scheduler: *Scheduler, thread: *Thread, thread_id: u64, thread_virtual_address_space: *VirtualAddressSpace, privilege_level: PrivilegeLevel, thread_type: Thread.Type, entry_point: u64, thread_stack: ThreadStack) void {
    scheduler.lock.assert_locked();
    //if (true) @panic("implement idle threads");

    thread.all_item = Thread.ListItem.new(thread);
    thread.queue_item = Thread.ListItem.new(thread);
    scheduler.all_threads.append(&thread.all_item, thread) catch @panic("wtf");

    thread.address_space = thread_virtual_address_space;
    thread.privilege_level = privilege_level;
    thread.id = thread_id;
    thread.type = thread_type;
    thread.cpu = null;
    thread.state = .active;
    thread.executing = false;

    thread.kernel_stack_base = thread_stack.kernel.address;
    thread.kernel_stack_size = thread_stack.kernel.size;
    thread.user_stack_base = thread_stack.user.address;
    thread.user_stack_size = thread_stack.user.size;

    thread.context = Context.new(thread, entry_point);
    if (thread.type == .normal) {
        // TODO: don't hardcode this
        const syscall_queue_entry_count = 256;
        thread.syscall_manager = switch (privilege_level) {
            .user => Syscall.KernelManager.new(thread.address_space, syscall_queue_entry_count),
            .kernel => .{ .kernel = null, .user = null },
        };

        if (privilege_level == .user) {
            // TODO: be more careful about virtual and physical addresses
            @panic("todo framebuffer scheduler");
            //const primary_graphics = kernel.device_manager.get_primary_graphics();
            //const primary_framebuffer = primary_graphics.framebuffer;
            //const framebuffer_kernel_virtual_address = VirtualAddress.new(@ptrToInt(primary_framebuffer.bytes));
            //common.log.scoped(.InitializeThread).debug("Trying to find out framebuffer physical address out of this virtual address: {}", .{framebuffer_kernel_virtual_address});
            //const framebuffer_physical_address = thread_virtual_address_space.translate_address(framebuffer_kernel_virtual_address) orelse unreachable;
            //const framebuffer_virtual_address = VirtualAddress.new(framebuffer_physical_address.value);
            //thread_virtual_address_space.map_extended(framebuffer_physical_address, framebuffer_virtual_address, common.align_forward(primary_framebuffer.stride * primary_framebuffer.height, arch.page_size), .{ .write = true, .user = true }, .no) catch unreachable;
            //thread.framebuffer = thread_virtual_address_space.heap.allocator.create(common.Framebuffer) catch unreachable;
            //const framebuffer = PhysicalAddress.new(@ptrToInt(thread.framebuffer)).to_higher_half_virtual_address().access(*common.Framebuffer);
            //framebuffer.* = primary_framebuffer;
            //framebuffer.bytes = framebuffer_virtual_address.access([*]u8);
        } else {
            // Index out of bounds
            //const primary_graphics = kernel.device_manager.get_primary_graphics();
            //const primary_framebuffer = primary_graphics.get_main_framebuffer();
            //thread.framebuffer = primary_framebuffer;
        }

        scheduler.active_threads.append(&thread.queue_item, thread) catch @panic("wtf");
    }
}
