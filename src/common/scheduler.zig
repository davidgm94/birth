const Scheduler = @This();

const kernel = @import("root");
const common = @import("../common.zig");
const drivers = @import("../drivers.zig");
const context = @import("context");

const VirtualAddressSpace = common.VirtualAddressSpace;
const VirtualAddress = common.VirtualAddress;
const PhysicalMemoryRegion = common.PhysicalMemoryRegion;
const PhysicalAddressSpace = common.PhysicalAddressSpace;
const Thread = common.Thread;

const TODO = common.TODO;
const log = common.log.scoped(.Scheduler);
const Allocator = common.Allocator;

const PrivilegeLevel = common.PrivilegeLevel;

pub const Context = common.arch.Context;

lock: common.arch.Spinlock,
thread_pool: [8192]Thread,
thread_id: u64,

pub fn init(scheduler: *Scheduler) void {
    _ = scheduler;
    log.debug("TODO: initialize scheduler", .{});
    //test_threads(1);
    //test_userspace();
}

pub fn yield(scheduler: *Scheduler, arch_context: *Context) void {
    const current_cpu = common.arch.get_current_thread().cpu.?;
    if (current_cpu.spinlock_count > 0) {
        @panic("spins active when yielding");
    }
    common.arch.disable_interrupts();
    scheduler.lock.acquire();
    var old_address_space: *VirtualAddressSpace = undefined;
    if (scheduler.lock.were_interrupts_enabled != 0) @panic("ffff");
    const current_thread = common.arch.get_current_thread();
    current_thread.context = arch_context;
    old_address_space = current_thread.address_space;
    const new_thread = scheduler.pick_thread();
    new_thread.cpu = current_thread.cpu;
    new_thread.time_slices += 1;
    // TODO: idle

    //log.debug("RSP: 0x{x}", .{context.rsp});
    //log.debug("Stack top: 0x{x}", .{new_thread.kernel_stack_base.value + new_thread.kernel_stack_size});
    //common.runtime_assert(@src(), context.rsp < new_thread.kernel_stack_base.value + new_thread.kernel_stack_size);

    //common.arch.next_timer(1);
    //log.debug("New thread address: 0x{x}", .{@ptrToInt(&new_thread)});
    //log.debug("New address space offset: 0x{x}", .{@ptrToInt(&new_thread) + @offsetOf(Thread, "address_space")});
    //log.debug("New thread address: 0x{x}", .{@intToPtr(*u64, @ptrToInt(&new_thread) + @offsetOf(Thread, "address_space")).*});
    if (false) {
        common.arch.switch_context(new_thread.context, new_thread.address_space, new_thread.kernel_stack.value, new_thread, old_address_space);
    } else {
        new_thread.context.check(@src());
        log.debug("About to do the crime", .{});
        common.arch.switch_context_preamble();
        new_thread.context.check(@src());
        common.arch.switch_address_spaces_if_necessary(new_thread.address_space);
        new_thread.context.check(@src());

        common.arch.set_argument(0, @ptrToInt(new_thread.context));
        common.arch.set_argument(1, @ptrToInt(new_thread));
        common.arch.set_argument(2, @ptrToInt(old_address_space));
        common.arch.set_new_stack(new_thread.kernel_stack.value);
        asm volatile (
            \\call post_context_switch
        );
        common.arch.interrupts_epilogue();

        @panic("wtfffF");
    }
}

pub fn spawn_thread(scheduler: *Scheduler, virtual_address_space: *VirtualAddressSpace, privilege_level: PrivilegeLevel, entry_point: u64) *Thread {
    // TODO: lock
    const new_thread_id = scheduler.thread_id;
    const thread_index = new_thread_id % scheduler.thread_pool.len;
    var thread = &scheduler.thread_pool[thread_index];
    scheduler.thread_id += 1;

    // TODO: should we always use the same address space for kernel tasks?
    thread.address_space = virtual_address_space;

    var kernel_stack_size: u64 = 0x5000;
    const user_stack_reserve: u64 = switch (privilege_level) {
        .kernel => kernel_stack_size,
        .user => 0x400000,
    };
    const user_stack_commit: u64 = switch (privilege_level) {
        .kernel => 0,
        .user => 0x10000,
    };
    var user_stack: VirtualAddress = undefined;
    // TODO: implemented idle thread

    // TODO: should this be kernel virtual address space?
    // TODO: this may crash
    const kernel_stack = virtual_address_space.allocate(kernel_stack_size, null, .{ .write = true }) catch @panic("unable to allocate the kernel stack");
    common.runtime_assert(@src(), kernel_stack.is_higher_half());
    user_stack = switch (privilege_level) {
        .kernel => kernel_stack,
        .user => blk: {
            // TODO: lock
            common.runtime_assert(@src(), common.is_aligned(user_stack_reserve, context.page_size));
            const user_stack_allocation = virtual_address_space.allocate(user_stack_reserve, null, .{ .write = true, .user = true }) catch @panic("user stack");
            break :blk user_stack_allocation;

            //const user_stack_physical_address = kernel_physical_address_space.allocate_pages(common.bytes_to_pages(user_stack_reserve, page_size, .must_be_exact)) orelse unreachable;
            //const user_stack_physical_region = PhysicalMemoryRegion.new(user_stack_physical_address, user_stack_reserve);
            //const user_stack_base_virtual_address = VirtualAddress.new(0x5000_0000_0000);
            //user_stack_physical_region.map(thread.address_space, user_stack_base_virtual_address, VirtualAddressSpace.Flags.from_flags(&.{ .read_write, .user }));

            //break :blk user_stack_base_virtual_address;
        },
    };
    thread.privilege_level = privilege_level;
    log.debug("Thread privilege: {}", .{thread.privilege_level});
    thread.kernel_stack_base = kernel_stack;
    thread.kernel_stack_size = kernel_stack_size;
    thread.user_stack_base = switch (privilege_level) {
        .kernel => VirtualAddress.new(0),
        .user => user_stack,
    };
    log.debug("User stack address: 0x{x}", .{thread.user_stack_base.value});
    thread.user_stack_reserve = user_stack_reserve;
    thread.user_stack_commit = user_stack_commit;
    thread.id = new_thread_id;
    thread.type = .normal;
    common.runtime_assert(@src(), thread.type == .normal);
    thread.current_thread = thread;
    thread.cpu = null;

    if (thread.type != .idle) {
        log.debug("Creating arch-specific thread initialization", .{});
        // TODO: hack
        thread.context = switch (privilege_level) {
            .kernel => common.arch.Context.new(thread, entry_point),
            .user => common.arch.Context.new(thread, entry_point),
        };
    }

    return thread;
}

pub fn load_executable(scheduler: *Scheduler, kernel_address_space: *VirtualAddressSpace, privilege_level: PrivilegeLevel, physical_address_space: *PhysicalAddressSpace, drive: *drivers.Filesystem, executable_filename: []const u8) *Thread {
    common.runtime_assert(@src(), kernel_address_space.privilege_level == .kernel);
    common.runtime_assert(@src(), privilege_level == .user);
    const executable_file = drive.read_file(drive, @ptrToInt(kernel_address_space), executable_filename);
    const user_virtual_address_space = kernel_address_space.heap.allocator.create(VirtualAddressSpace) catch @panic("wtf");
    VirtualAddressSpace.initialize_user_address_space(user_virtual_address_space, physical_address_space, kernel_address_space) orelse @panic("wtf2");
    const elf_result = common.ELF.parse(.{ .user = user_virtual_address_space, .kernel = kernel_address_space, .physical = physical_address_space }, executable_file);
    //common.runtime_assert(@src(), elf_result.entry_point == 0x200110);
    const thread = scheduler.spawn_thread(user_virtual_address_space, privilege_level, elf_result.entry_point);

    return thread;
}

pub fn terminate(thread: *Thread) void {
    _ = thread;
    TODO(@src());
}

fn pick_thread(scheduler: *Scheduler) *Thread {
    const current_thread = common.arch.get_current_thread();
    const current_thread_id = current_thread.id;
    common.runtime_assert(@src(), current_thread_id < scheduler.thread_id);
    //const next_thread_index = kernel.arch.read_timestamp() % thread_id;
    const next_thread_index = 0;
    const new_thread = &scheduler.thread_pool[next_thread_index];
    return new_thread;
}
