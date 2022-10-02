const CPU = @This();

const common = @import("common");
const assert = common.assert;
const log = common.log.scoped(.CPU);

const kernel = @import("kernel");

const RNU = @import("RNU");
const PhysicalAddress = RNU.PhysicalAddress;
const Scheduler = RNU.Scheduler;
const Thread = RNU.Thread;
const VirtualAddressSpace = RNU.VirtualAddressSpace;

const arch = @import("arch");
const page_size = arch.page_size;
const TLS = arch.TLS;
const x86_64 = arch.x86_64;
const CPUID = x86_64.CPUID;
const GDT = x86_64.GDT;
const IDT = x86_64.IDT;
const interrupts = x86_64.interrupts;
const io = x86_64.io;
const LAPIC = x86_64.LAPIC;
const PIC = x86_64.PIC;
const registers = x86_64.registers;
const cr0 = registers.cr0;
const cr4 = registers.cr4;
const Syscall = x86_64.Syscall;
const TSS = x86_64.TSS;

lapic: LAPIC,
spinlock_count: u64 = 0,
id: u32 = 0,
gdt: GDT.Table,
tss: TSS.Struct,
idt: IDT,
idle_thread: *Thread,
timestamp_ticks_per_ms: u64 = 0,
ready: bool,

pub fn early_bsp_bootstrap() void {
    arch.max_physical_address_bit = CPUID.get_max_physical_address_bit();
    // Generate enough bootstraping structures to make some early stuff work
    TLS.preset_bsp(&kernel.scheduler, &kernel.bootstrap_context.thread, &kernel.bootstrap_context.process, &kernel.bootstrap_context.cpu);
    kernel.bootstrap_context.thread.context = &kernel.bootstrap_context.context;

    // @ZigBug: @ptrCast here crashes the compiler
    kernel.scheduler.cpus = @intToPtr([*]CPU, @ptrToInt(&kernel.bootstrap_context.cpu))[0..1];
}

pub fn start(cpu: *CPU, scheduler: *Scheduler, virtual_address_space: *VirtualAddressSpace) void {
    cpu.ready = false;
    cpu.spinlock_count = 0;
    enable_cpu_features();
    // This assumes the CPU processor local storage is already properly setup here
    cpu.gdt.setup();
    // Reload GS after loading GDT (it resets it)
    TLS.preset(scheduler, cpu);
    cpu.init_interrupts();
    cpu.init_apic(virtual_address_space);
    Syscall.enable();

    cpu.tss = TSS.Struct{};
    cpu.gdt.update_tss(&cpu.tss);

    cpu.init_timer();

    log.debug("Scheduler pre-initialization finished!", .{});
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

    assert(!cr0.get_bit(.CD));
    assert(!cr0.get_bit(.NW));
}

pub fn init_interrupts(cpu: *CPU) void {
    // Initialize interrupts
    log.debug("Initializing interrupts", .{});
    PIC.disable();
    interrupts.install_handlers(&cpu.idt);
    log.debug("Installed interrupt handlers", .{});
    cpu.idt.load();
    log.debug("Loaded IDT", .{});
    interrupts.enable();
    log.debug("Enabled interrupts", .{});
}

var map_lapic_address_times_called: u8 = 0;
/// This function is only meant to be called once
pub fn map_lapic() void {
    if (@ptrCast(*volatile u8, &map_lapic_address_times_called).* != 0) @panic("Trying to map LAPIC address more than once");
    defer _ = @atomicRmw(u8, &map_lapic_address_times_called, .Add, 1, .SeqCst);

    const apic_base = registers.get_apic_base();
    const lapic_physical_address = PhysicalAddress.new(apic_base);
    const lapic_virtual_address = lapic_physical_address.to_higher_half_virtual_address();
    const lapic_page_count = 1;
    const lapic_flags = VirtualAddressSpace.Flags{ .write = true, .cache_disable = true };
    kernel.virtual_address_space.map_reserved_region(lapic_physical_address, lapic_virtual_address, lapic_page_count * page_size, lapic_flags);
}

pub fn init_timer(cpu: *CPU) void {
    interrupts.disable();
    const timer_calibration_start = read_timestamp();
    var times_i: u64 = 0;
    const times = 8;
    cpu.timestamp_ticks_per_ms = 0;

    cpu.lapic.write(.TIMER_INITCNT, common.max_int(u32));

    while (times_i < times) : (times_i += 1) {
        io.write(u8, io.Ports.PIT_command, 0x30);
        io.write(u8, io.Ports.PIT_data, 0xa9);
        io.write(u8, io.Ports.PIT_data, 0x04);

        while (true) {
            io.write(u8, io.Ports.PIT_command, 0xe2);
            if (io.read(u8, io.Ports.PIT_data) & (1 << 7) != 0) break;
        }
    }

    cpu.lapic.ticks_per_ms = common.max_int(u32) - cpu.lapic.read(.TIMER_CURRENT_COUNT) >> 4;
    const timer_calibration_end = read_timestamp();
    cpu.timestamp_ticks_per_ms = (timer_calibration_end - timer_calibration_start) >> 3;
    interrupts.enable();

    log.debug("Timer initialized!", .{});
}

pub fn sleep_on_tsc(ms: u32) void {
    const current_thread = TLS.get_current();
    const cpu = current_thread.cpu orelse @panic("cpu");
    const sleep_tick_count = ms * cpu.timestamp_ticks_per_ms;
    const time_start = read_timestamp();
    while (true) {
        const time_now = read_timestamp();
        const ticks_passed = time_now - time_start;
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

pub fn init_apic(cpu: *CPU, virtual_address_space: *VirtualAddressSpace) void {
    const spurious_value = @as(u32, 0x100) | spurious_vector;
    log.debug("Local storage: 0x{x}", .{@ptrToInt(cpu)});
    // TODO: x2APIC
    const apic_physical_address = registers.get_apic_base();
    log.debug("APIC physical address: 0x{x}", .{apic_physical_address});
    assert(apic_physical_address != 0);
    const old_lapic_id = cpu.lapic.id;
    cpu.lapic = LAPIC.new(virtual_address_space, PhysicalAddress.new(apic_physical_address), old_lapic_id);
    cpu.lapic.write(.SPURIOUS, spurious_value);
    // TODO: getting the lapic id from a LAPIC register is not reporting good ids. Why?
    //const lapic_id = cpu.lapic.read(.LAPIC_ID);
    //log.debug("Old LAPIC id: {}. New LAPIC id: {}", .{ old_lapic_id, lapic_id });
    //assert(lapic_id == cpu.lapic.id);
    log.debug("APIC enabled", .{});
}

pub fn make_thread_idle(cpu: *CPU) noreturn {
    _ = cpu;
    asm volatile ("int $0x40");
    //cpu.lapic.next_timer(1);

    while (true) {
        asm volatile (
            \\sti
            \\hlt
        );
    }
}
