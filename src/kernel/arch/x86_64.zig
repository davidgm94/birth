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

pub const page_size = common.arch.check_page_size(0x1000);
pub const entry = @import("x86_64/entry.zig");

var bootstrap_cpu: common.arch.CPU = undefined;
var bootstrap_thread: common.Thread = undefined;

const x86_64 = common.arch.x86_64;
pub fn preinit_bsp() void {
    // @ZigBug: @ptrCast here crashes the compiler
    kernel.cpus = @intToPtr([*]common.arch.CPU, @ptrToInt(&bootstrap_cpu))[0..1];
    bootstrap_thread.local_storage.cpu = &bootstrap_cpu;
    bootstrap_thread.local_storage.local_storage = &bootstrap_thread.local_storage;
    x86_64.set_local_storage(&bootstrap_thread.local_storage);
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
    new_thread.local_storage.local_storage = &new_thread.local_storage;
    x86_64.set_local_storage(new_thread.local_storage.local_storage);
    const should_swap_gs = x86_64.cs.read() != 0x28;
    // TODO: checks
    //const new_thread = current_thread.time_slices == 1;

    // TODO: close reference or dettach address space
    _ = old_address_space;
    new_thread.last_known_execution_address = context.rip;

    new_thread.local_storage.cpu.lapic.end_of_interrupt();
    if (x86_64.are_interrupts_enabled()) @panic("interrupts enabled");
    if (new_thread.local_storage.cpu.spinlock_count > 0) @panic("spinlocks active");
    // TODO: profiling
    if (should_swap_gs) asm volatile ("swapgs");
}

pub export fn syscall_entry_point() callconv(.Naked) void {
    comptime {
        common.comptime_assert(@offsetOf(common.arch.CPU, "current_thread") == 0x08);
        common.comptime_assert(@offsetOf(common.Thread, "kernel_stack") == 0);
    }
    asm volatile (
        \\mov %%gs:[0], %%r15
        \\add %[offset], %%r15
        \\mov (%%r15), %%r15
        \\mov (%%r15), %%r15
        \\mov %%r15, %%rbp
        \\push %%rbp
        \\mov %%rbp, %%rsp
        \\sub $0x10, %%rsp
        :
        : [offset] "i" (@intCast(u8, @offsetOf(common.arch.CPU, "current_thread"))),
    );

    const syscall_number = x86_64.rax.read();
    _ = kernel.syscall.syscall_handlers[syscall_number](0, 0, 0, 0);
    asm volatile ("sysret");
}
