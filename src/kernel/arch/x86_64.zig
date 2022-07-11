const kernel = @import("root");
const common = @import("common");
const drivers = @import("../../drivers.zig");
const PCI = drivers.PCI;
const NVMe = drivers.NVMe;
const Virtio = drivers.Virtio;
const Disk = drivers.Disk;
const Filesystem = drivers.Filesystem;
const RNUFS = drivers.RNUFS;

const TODO = common.TODO;
const Allocator = common.Allocator;
const PhysicalAddress = common.PhysicalAddress;
const PhysicalAddressSpace = common.PhysicalAddressSpace;
const PhysicalMemoryRegion = common.PhysicalMemoryRegion;
const VirtualAddress = common.VirtualAddress;
const VirtualAddressSpace = common.VirtualAddressSpace;
const VirtualMemoryRegion = common.VirtualMemoryRegion;

const log = common.log.scoped(.x86_64);

pub const entry = @import("x86_64/entry.zig");

var bootstrap_cpu: common.arch.CPU = undefined;
var bootstrap_thread: common.Thread = undefined;

const x86_64 = common.arch.x86_64;
pub fn preinit_bsp() void {
    // @ZigBug: @ptrCast here crashes the compiler
    kernel.cpus = @intToPtr([*]common.arch.CPU, @ptrToInt(&bootstrap_cpu))[0..1];
    bootstrap_thread.current_thread = &bootstrap_thread;
    bootstrap_thread.cpu = &bootstrap_cpu;
    x86_64.set_current_thread(&bootstrap_thread);
    x86_64.IA32_KERNEL_GS_BASE.write(0);
}
//
//pub extern fn switch_context(new_context: *Context, new_address_space: *AddressSpace, kernel_stack: u64, new_thread: *Thread, old_address_space: *VirtualAddressSpace) callconv(.C) void;
export fn switch_context() callconv(.Naked) void {
    asm volatile (
        \\cli
        // Compare address spaces and switch if they are not the same
        \\mov (%%rsi), %%rsi
        \\mov %%cr3, %%rax
        \\cmp %%rsi, %%rax
        \\je 0f
        \\mov %%rsi, %%cr3
        \\0:
        \\mov %%rdi, %%rsp
        \\mov %%rcx, %%rsi
        \\mov %%r8, %%rdx
    );

    asm volatile (
        \\call post_context_switch
    );

    x86_64.interrupts.epilogue();

    unreachable;
}

export fn post_context_switch(context: *common.arch.x86_64.Context, new_thread: *common.Thread, old_address_space: *VirtualAddressSpace) callconv(.C) void {
    log.debug("Context switching", .{});
    if (kernel.scheduler.lock.were_interrupts_enabled) {
        @panic("interrupts were enabled");
    }
    kernel.scheduler.lock.release();
    //common.runtime_assert(@src(), context == new_thread.context);
    //common.runtime_assert(@src(), context.rsp < new_thread.kernel_stack_base.value + new_thread.kernel_stack_size);
    context.check(@src());
    common.runtime_assert(@src(), new_thread.current_thread == new_thread);
    x86_64.set_current_thread(new_thread);
    const new_cs_user_bits = @truncate(u2, context.cs);
    const old_cs_user_bits = @truncate(u2, x86_64.cs.read());
    const should_swap_gs = new_cs_user_bits == ~old_cs_user_bits;

    // TODO: checks
    //const new_thread = current_thread.time_slices == 1;

    // TODO: close reference or dettach address space
    _ = old_address_space;
    new_thread.last_known_execution_address = context.rip;

    const cpu = new_thread.cpu orelse @panic("CPU pointer is missing in the post-context switch routine");
    cpu.lapic.end_of_interrupt();
    if (x86_64.are_interrupts_enabled()) @panic("interrupts enabled");
    if (cpu.spinlock_count > 0) @panic("spinlocks active");
    // TODO: profiling
    if (should_swap_gs) asm volatile ("swapgs");
}

extern fn syscall_handler(arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) callconv(.C) u64;

pub export fn syscall_entry_point() callconv(.Naked) void {
    comptime {
        common.comptime_assert(@offsetOf(common.Thread, "kernel_stack") == 8);
    }
    // This sets up the kernel stack before actually starting to run kernel code
    asm volatile (
        \\swapgs
        // Save RFLAGS (R11), next instruction address after sysret (RCX) and user stack (RSP)
        \\mov %%r11, %%r12
        \\mov %%rcx, %%r13
        \\mov %%rsp, %%r14
        // Pass original RCX (4th argument)
        \\mov %%rax, %%rcx
        // Get kernel stack
        \\mov %%gs:[0], %%r15
        \\add %[offset], %%r15
        \\mov (%%r15), %%r15
        \\mov %%r15, %%rbp
        // Use kernel stack
        \\push %%rbp
        \\mov %%rbp, %%rsp
        \\sub $0x10, %%rsp
        :
        : [offset] "i" (@intCast(u8, @offsetOf(common.Thread, "kernel_stack"))),
    );

    // TODO: try call *(%rax) to avoid having another layer

    asm volatile (
        \\mov %%rdi, %%rax
        \\cmp %[syscall_count], %%rax
        \\jge 0f
        \\shl $0x03, %%rax
        \\add %[handler_base_array], %%rax
        \\call *(%%rax)
        \\add $0x10, %%rsp
        \\pop %%rbp
        \\mov %%r14, %%rsp
        \\mov %%r12, %%r11
        \\mov %%r13, %%rcx
        \\swapgs
        \\sysret
        // TODO: we should crash if the index of a syscall is wrong
        \\0:
        \\cli
        \\hlt
        :
        : [syscall_count] "i" (kernel.syscall.syscall_handlers.len),
          [handler_base_array] "i" (@ptrToInt(&kernel.syscall.syscall_handlers)),
    );

    unreachable;
}
