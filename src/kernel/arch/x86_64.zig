pub const entry = @import("x86_64/entry.zig");

const std = @import("../../common/std.zig");

const Bitflag = @import("../../common/bitflag.zig").Bitflag;
const crash = @import("../crash.zig");
const context = @import("../context.zig");
const kernel = @import("../kernel.zig");
const PhysicalAddress = @import("../physical_address.zig");
const PhysicalAddressSpace = @import("../physical_address_space.zig");
const Scheduler = @import("../scheduler.zig");
const Thread = @import("../thread.zig");
const VirtualAddress = @import("../virtual_address.zig");
const VirtualAddressSpace = @import("../virtual_address_space.zig");

const Context = @import("x86_64/context.zig");
const GDT = @import("x86_64/gdt.zig");
const IDT = @import("x86_64/idt.zig");
const interrupts = @import("x86_64/interrupts.zig");
const registers = @import("x86_64/registers.zig");
const SerialWriter = @import("x86_64/serial_writer.zig");
const Syscall = @import("x86_64/syscall.zig");
const Stivale2 = @import("x86_64/limine/stivale2/stivale2.zig");
const TSS = @import("x86_64/tss.zig");

pub const DefaultLogWriter = SerialWriter;
pub const Spinlock = @import("x86_64/spinlock.zig");
pub const TLS = @import("x86_64/tls.zig");

const log = std.log.scoped(.x86_64);
const TODO = crash.TODO;
const panic = crash.panic;

var _zero: u64 = 0;

pub fn cpu_start(virtual_address_space: *VirtualAddressSpace) void {
    const current_thread = TLS.get_current();
    const cpu = current_thread.cpu orelse @panic("cpu");
    enable_cpu_features();
    // This assumes the CPU processor local storage is already properly setup here
    cpu.gdt.initial_setup(cpu.id);
    interrupts.init(&cpu.idt);
    enable_apic(virtual_address_space);
    Syscall.enable();

    cpu.shared_tss = TSS.Struct{};
    cpu.gdt.update_tss(&cpu.shared_tss);

    log.debug("Scheduler pre-initialization finished!", .{});
}



pub fn get_memory_map() kernel.Memory.Map {
    const memory_map_struct = Stivale2.find(Stivale2.Struct.MemoryMap) orelse @panic("Stivale had no RSDP struct");
    return Stivale2.process_memory_map(memory_map_struct);
}

fn is_canonical_address(address: u64) bool {
    const sign_bit = address & (1 << 63) != 0;
    const significant_bit_count = page_table_level_count_to_bit_map(page_table_level_count);
    var i: u8 = 63;
    while (i >= significant_bit_count) : (i -= 1) {
        const bit = address & (1 << i) != 0;
        if (bit != sign_bit) return false;
    }

    return true;
}

pub const page_table_level_count = 4;

fn page_table_level_count_to_bit_map(level: u8) u8 {
    return switch (level) {
        4 => 48,
        5 => 57,
        else => @panic("invalid page table level count\n"),
    };
}


pub inline fn next_timer(ms: u32) void {
    const current_cpu = TLS.get_current().cpu orelse @panic("current cpu not set");
    current_cpu.lapic.next_timer(ms);
}

pub inline fn spinloop_without_wasting_cpu() noreturn {
    while (true) {
        asm volatile (
            \\cli
            \\hlt
        );
        asm volatile ("pause" ::: "memory");
    }
}

pub fn post_context_switch(arch_context: *Context, new_thread: *Thread, old_address_space: *VirtualAddressSpace) callconv(.C) void {
    log.debug("Context switching", .{});
    if (@import("root").scheduler.lock.were_interrupts_enabled != 0) {
        @panic("interrupts were enabled");
    }
    kernel.scheduler.lock.release();
    //std.assert(context == new_thread.context);
    //std.assert(context.rsp < new_thread.kernel_stack_base.value + new_thread.kernel_stack_size);
    arch_context.check(@src());
    std.assert(new_thread.current_thread == new_thread);
    TLS.set_current(new_thread);
    const new_cs_user_bits = @truncate(u2, arch_context.cs);
    const old_cs_user_bits = @truncate(u2, cs.read());
    const should_swap_gs = new_cs_user_bits == ~old_cs_user_bits;

    // TODO: checks
    //const new_thread = current_thread.time_slices == 1;

    // TODO: close reference or dettach address space
    _ = old_address_space;
    //new_thread.last_known_execution_address = arch_context.rip;

    const cpu = new_thread.cpu orelse @panic("CPU pointer is missing in the post-context switch routine");
    cpu.lapic.end_of_interrupt();
    if (interrupts.are_enabled()) @panic("interrupts enabled");
    if (cpu.spinlock_count > 0) @panic("spinlocks active");
    // TODO: profiling
    if (should_swap_gs) asm volatile ("swapgs");
}

pub inline fn signal_end_of_interrupt(cpu: *CPU) void {
    cpu.lapic.end_of_interrupt();
}

pub inline fn legacy_actions_before_context_switch(new_thread: *Thread) void {
    const new_cs_user_bits = @truncate(u2, new_thread.context.cs);
    const old_cs_user_bits = @truncate(u2, cs.read());
    const should_swap_gs = new_cs_user_bits == ~old_cs_user_bits;
    if (should_swap_gs) asm volatile ("swapgs");
}

pub const rax = registers.rax;
pub const rbx = registers.rbx;
pub const rcx = registers.rcx;
pub const rdx = registers.rdx;
pub const rbp = registers.rbp;
pub const rsp = registers.rsp;
pub const rsi = registers.rsi;
pub const rdi = registers.rdi;
pub const r8 = registers.r8;
pub const r9 = registers.r9;
pub const r10 = registers.r10;
pub const r11 = registers.r11;
pub const r12 = registers.r12;
pub const r13 = registers.r13;
pub const r14 = registers.r14;
pub const r15 = registers.r15;

pub const cs = registers.cs;
pub const gs = registers.gs;

pub const dr0 = registers.dr0;
pub const dr1 = registers.dr1;
pub const dr2 = registers.dr2;
pub const dr3 = registers.dr3;
pub const dr4 = registers.dr4;
pub const dr5 = registers.dr5;
pub const dr6 = registers.dr6;
pub const dr7 = registers.dr7;

pub const cr0 = registers.cr0;
pub const cr2 = registers.cr2;
pub const cr3 = registers.cr3;
pub const cr4 = registers.cr4;
pub const cr8 = registers.cr8;

pub const RFLAGS = registers.RFLAGS;

//pub const PAT = SimpleMSR(0x277);
pub const IA32_STAR = registers.IA32_STAR;
pub const IA32_LSTAR = registers.IA32_LSTAR;
pub const IA32_FMASK = registers.IA32_FMASK;
pub const IA32_FS_BASE = registers.IA32_FS_BASE;
pub const IA32_GS_BASE = registers.IA32_GS_BASE;
pub const IA32_KERNEL_GS_BASE = registers.IA32_KERNEL_GS_BASE;
pub const IA32_EFER = registers.IA32_EFER;
pub const IA32_APIC_BASE = registers.IA32_APIC_BASE;
