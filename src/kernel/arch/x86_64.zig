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

pub var timestamp_ticks_per_ms: u64 = 0;

pub fn init_timer() void {
    interrupts.disable();
    const bsp = &kernel.scheduler.cpus[0];
    std.assert(bsp.is_bootstrap);
    const timer_calibration_start = read_timestamp();
    log.debug("About to use LAPIC", .{});
    bsp.lapic.write(.TIMER_INITCNT, std.max_int(u32));
    log.debug("After to use LAPIC", .{});
    var times_i: u64 = 0;
    const times = 8;

    while (times_i < times) : (times_i += 1) {
        io_write(u8, IOPort.PIT_command, 0x30);
        io_write(u8, IOPort.PIT_data, 0xa9);
        io_write(u8, IOPort.PIT_data, 0x04);

        while (true) {
            io_write(u8, IOPort.PIT_command, 0xe2);
            if (io_read(u8, IOPort.PIT_data) & (1 << 7) != 0) break;
        }
    }
    bsp.lapic.ticks_per_ms = std.max_int(u32) - bsp.lapic.read(.TIMER_CURRENT_COUNT) >> 4;
    const timer_calibration_end = read_timestamp();
    timestamp_ticks_per_ms = (timer_calibration_end - timer_calibration_start) >> 3;
    interrupts.enable();

    log.debug("Timer initialized!", .{});
}

pub fn sleep_on_tsc(ms: u32) void {
    const sleep_tick_count = ms * timestamp_ticks_per_ms;
    const start = read_timestamp();
    while (true) {
        const now = read_timestamp();
        const ticks_passed = now - start;
        if (ticks_passed >> 3 >= sleep_tick_count) break;
    }
}

pub inline fn read_timestamp() u64 {
    var my_rdx: u64 = undefined;
    var my_rax: u64 = undefined;

    asm volatile (
        \\rdtsc
        : [rax] "={rax}" (my_rax),
          [rdx] "={rdx}" (my_rdx),
    );

    return my_rdx << 32 | my_rax;
}

pub const spurious_vector: u8 = 0xFF;

pub fn enable_apic(virtual_address_space: *VirtualAddressSpace) void {
    const spurious_value = @as(u32, 0x100) | spurious_vector;
    const cpu = TLS.get_current().cpu orelse @panic("cannot get cpu");
    log.debug("Local storage: 0x{x}", .{@ptrToInt(cpu)});
    // TODO: x2APIC
    const ia32_apic = IA32_APIC_BASE.read();
    const apic_physical_address = get_apic_base(ia32_apic);
    log.debug("APIC physical address: 0x{x}", .{apic_physical_address});
    std.assert(apic_physical_address != 0);
    const old_lapic_id = cpu.lapic.id;
    cpu.lapic = LAPIC.new(virtual_address_space, PhysicalAddress.new(apic_physical_address), old_lapic_id);
    cpu.lapic.write(.SPURIOUS, spurious_value);
    // TODO: getting the lapic id from a LAPIC register is not reporting good ids. Why?
    //const lapic_id = cpu.lapic.read(.LAPIC_ID);
    //log.debug("Old LAPIC id: {}. New LAPIC id: {}", .{ old_lapic_id, lapic_id });
    //std.assert(lapic_id == cpu.lapic.id);
    log.debug("APIC enabled", .{});
}

var times_mapped: u64 = 0;
pub fn map_lapic(virtual_address_space: *VirtualAddressSpace) void {
    if (times_mapped != 0) @panic("called more than once");
    defer times_mapped += 1;

    const cpu = TLS.get_current().cpu orelse @panic("wtf");
    std.assert(cpu.id == 0);
    std.assert(cpu.is_bootstrap);

    const ia32_apic = IA32_APIC_BASE.read();
    const lapic_physical_address = PhysicalAddress.new(get_apic_base(ia32_apic));
    const lapic_virtual_address = lapic_physical_address.to_higher_half_virtual_address();
    virtual_address_space.map(lapic_physical_address, lapic_virtual_address, .{ .write = true, .cache_disable = true });
}

pub fn enable_cpu_features() void {
    // Initialize FPU
    var cr0_value = cr0.read();
    cr0_value.set_bit(.MP);
    cr0_value.set_bit(.NE);
    cr0.write(cr0_value);
    var cr4_value = cr4.read();
    cr4_value.set_bit(.OSFXSR);
    cr4_value.set_bit(.OSXMMEXCPT);
    cr4.write(cr4_value);

    // @TODO: what is this?
    const cw: u16 = 0x037a;
    asm volatile (
        \\fninit
        \\fldcw (%[cw])
        :
        : [cw] "r" (&cw),
    );

    std.assert(!cr0.get_bit(.CD));
    std.assert(!cr0.get_bit(.NW));
}

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

pub fn get_physical_address_memory_configuration() void {
    context.max_physical_address_bit = CPUID.get_max_physical_address_bit();
}

fn get_apic_base(ia32_apic_base: IA32_APIC_BASE.Flags) u32 {
    return @truncate(u32, ia32_apic_base.bits & 0xfffff000);
}

pub const CPUID = struct {
    eax: u32,
    ebx: u32,
    edx: u32,
    ecx: u32,

    /// Returns the maximum number bits a physical address is allowed to have in this CPU
    pub inline fn get_max_physical_address_bit() u6 {
        return @truncate(u6, cpuid(0x80000008).eax);
    }
};

pub inline fn cpuid(leaf: u32) CPUID {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var edx: u32 = undefined;
    var ecx: u32 = undefined;

    asm volatile (
        \\cpuid
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [edx] "={edx}" (edx),
          [ecx] "={ecx}" (ecx),
        : [leaf] "{eax}" (leaf),
    );

    return CPUID{
        .eax = eax,
        .ebx = ebx,
        .edx = edx,
        .ecx = ecx,
    };
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

pub fn bootstrap_stacks(cpus: []CPU, virtual_address_space: *VirtualAddressSpace, stack_size: u64) void {
    std.assert(std.is_aligned(stack_size, context.page_size));
    const cpu_count = cpus.len;
    const allocation_size = cpu_count * stack_size * 2;
    const stack_allocation = virtual_address_space.heap.allocator.allocBytes(context.page_size, allocation_size, 0, 0) catch @panic("wtf");
    const middle = allocation_size / 2;
    const base = @ptrToInt(stack_allocation.ptr);

    for (cpus) |*cpu, i| {
        const rsp_offset = base + (i * stack_size);
        const ist_offset = rsp_offset + middle;
        cpu.shared_tss.rsp[0] = rsp_offset + stack_size;
        cpu.shared_tss.IST[0] = ist_offset + stack_size;
    }
}

export fn thread_terminate(thread: *Thread) void {
    _ = thread;
    TODO();
}

pub inline fn switch_address_spaces_if_necessary(new_address_space: *VirtualAddressSpace) void {
    const current_cr3 = cr3.read_raw();
    if (current_cr3 != new_address_space.arch.cr3) {
        cr3.write_raw(new_address_space.arch.cr3);
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

pub fn preinit_bsp(scheduler: *Scheduler, virtual_address_space: *VirtualAddressSpace, bootstrap_context: *BootstrapContext) void {
    // @ZigBug: @ptrCast here crashes the compiler

    bootstrap_context.cpu.id = 0;
    bootstrap_context.thread.cpu = &bootstrap_context.cpu;
    bootstrap_context.thread.context = &bootstrap_context.context;
    bootstrap_context.thread.address_space = virtual_address_space;
    TLS.preset_bsp(&bootstrap_context.thread);
    TLS.set_current(&bootstrap_context.thread);

    scheduler.cpus = @intToPtr([*]CPU, @ptrToInt(&bootstrap_context.cpu))[0..1];
}

pub const BootstrapContext = struct {
    cpu: CPU,
    thread: Thread,
    context: Context,
};

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
