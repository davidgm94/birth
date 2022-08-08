const kernel = @import("root");
const common = @import("../../common.zig");
const drivers = @import("../../drivers.zig");
const context = @import("context");
const PCI = drivers.PCI;
const AHCI = drivers.AHCI;
const IDE = drivers.IDE;
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
const VirtualMemoryRegion = common.VirtualMemoryRegion;
const Scheduler = common.Scheduler;

const log = common.log.scoped(.x86_64);

pub const Stivale2 = @import("x86_64/limine/stivale2/stivale2.zig");
pub const Spinlock = @import("x86_64/spinlock.zig");
pub const DescriptorTable = @import("x86_64/descriptor_table.zig");
pub const PIC = @import("x86_64/pic.zig");
pub const IDT = @import("x86_64/idt.zig");
pub const GDT = @import("x86_64/gdt.zig");
pub const TSS = @import("x86_64/tss.zig");
pub const interrupts = @import("x86_64/interrupts.zig");
pub const paging = @import("x86_64/paging.zig");
pub const ACPI = @import("x86_64/acpi.zig");
pub const Syscall = @import("x86_64/syscall.zig");
/// This is just the arch-specific part of the address space
pub const VirtualAddressSpace = paging.VirtualAddressSpace;
pub const interrupts_epilogue = interrupts.epilogue;
const Thread = common.Thread;

pub const IOAPIC = struct {
    address: PhysicalAddress,
    gsi: u32,
    id: u8,

    pub inline fn read(apic: IOAPIC, register: u32) u32 {
        apic.address.access_kernel([*]volatile u32)[0] = register;
        return apic.address.access_kernel([*]volatile u32)[4];
    }

    pub inline fn write(apic: IOAPIC, register: u32, value: u32) void {
        apic.address.access_kernel([*]volatile u32)[0] = register;
        apic.address.access_kernel([*]volatile u32)[4] = value;
    }
};

pub const ISO = struct {
    gsi: u32,
    source_IRQ: u8,
    active_low: bool,
    level_triggered: bool,
};

pub var ioapic: IOAPIC = undefined;
pub var iso: []ISO = undefined;

var _zero: u64 = 0;

pub fn register_main_storage() void {
    kernel.main_storage = Filesystem.drivers.items[0];
}

pub fn drivers_init(virtual_address_space: *common.VirtualAddressSpace) !void {
    try init_block_drivers(virtual_address_space);
    log.debug("Initialized block drivers", .{});

    try init_graphics_drivers(virtual_address_space.heap.allocator);
    log.debug("Initialized graphics drivers", .{});
}

pub fn init_block_drivers(virtual_address_space: *common.VirtualAddressSpace) !void {
    AHCI.drivers = try AHCI.Initialization.callback(virtual_address_space, &PCI.controller);
    common.runtime_assert(@src(), Disk.drivers.items.len > 0);
    try drivers.Driver(Filesystem, RNUFS).init(virtual_address_space.heap.allocator, Disk.drivers.items[0]);
    // TODO: make ACPI and PCI controller standard
    // TODO: make a category for NVMe and standardize it there
    // INFO: this callback also initialize child drives
    //NVMe.driver = try NVMe.Initialization.callback(virtual_address_space, &PCI.controller);

    //Virtio.Block.driver = try Virtio.Block.from_pci(&PCI.controller);
    //common.runtime_assert(@src(), Disk.drivers.items.len == 2);
    //try drivers.Driver(Filesystem, RNUFS).init(virtual_address_space.heap.allocator, Disk.drivers.items[1]);
}

pub fn init_graphics_drivers(allocator: Allocator) !void {
    _ = allocator;
    log.debug("TODO: initialize graphics drivers", .{});
}

pub fn prepare_drivers(virtual_address_space: *common.VirtualAddressSpace, rsdp: PhysicalAddress) void {
    ACPI.init(virtual_address_space, rsdp);
    PCI.init(virtual_address_space);
}

pub var timestamp_ticks_per_ms: u64 = 0;

pub fn init_timer() void {
    disable_interrupts();
    const bsp = &kernel.scheduler.cpus[0];
    common.runtime_assert(@src(), bsp.is_bootstrap);
    const timer_calibration_start = read_timestamp();
    log.debug("About to use LAPIC", .{});
    bsp.lapic.write(.TIMER_INITCNT, common.max_int(u32));
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
    bsp.lapic.ticks_per_ms = common.max_int(u32) - bsp.lapic.read(.TIMER_CURRENT_COUNT) >> 4;
    const timer_calibration_end = read_timestamp();
    timestamp_ticks_per_ms = (timer_calibration_end - timer_calibration_start) >> 3;
    enable_interrupts();

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

var my_current_thread: *Thread = undefined;

pub inline fn preset_thread_pointer_bsp(current_thread: *Thread) void {
    my_current_thread = current_thread;
    // @ZigBug we need to inttoptr here
    thread_pointers = @intToPtr([*]*Thread, @ptrToInt(&my_current_thread))[0..1];
    preset_thread_pointer(0);
}

pub inline fn preset_thread_pointer(index: u64) void {
    IA32_GS_BASE.write(@ptrToInt(&thread_pointers[index]));
    IA32_KERNEL_GS_BASE.write(0);
}

var thread_pointers: []*Thread = undefined;

/// This is supposed to be called only by the BSP thread/CPU
pub inline fn allocate_and_setup_thread_pointers(virtual_address_space: *common.VirtualAddressSpace, scheduler: *common.Scheduler) void {
    const cpu_count = scheduler.cpus.len;
    const bsp_thread = thread_pointers[0];
    common.runtime_assert(@src(), bsp_thread.cpu.?.is_bootstrap);
    thread_pointers = virtual_address_space.heap.allocator.alloc(*Thread, cpu_count) catch @panic("wtf");
    common.runtime_assert(@src(), scheduler.all_threads.count == scheduler.thread_buffer.element_count);
    common.runtime_assert(@src(), scheduler.all_threads.count < Thread.Buffer.Bucket.size);
    for (thread_pointers) |*tp, i| {
        tp.* = &scheduler.thread_buffer.first.?.data[i];
    }
    common.runtime_assert(@src(), thread_pointers[0] == bsp_thread);
    IA32_GS_BASE.write(@ptrToInt(&thread_pointers[0]));
}

pub inline fn set_current_thread(current_thread: *Thread) void {
    const current_cpu = current_thread.cpu orelse @panic("Wtf");
    thread_pointers[current_cpu.id] = current_thread;
}

pub inline fn get_current_thread() *Thread {
    return asm volatile (
        \\mov %%gs:[0], %[result]
        : [result] "=r" (-> *Thread),
    );
}

pub const timer_interrupt = 0x40;
pub const interrupt_vector_msi_start = 0x70;
pub const interrupt_vector_msi_count = 0x40;
pub const spurious_vector: u8 = 0xFF;

pub fn enable_apic(virtual_address_space: *common.VirtualAddressSpace) void {
    const spurious_value = @as(u32, 0x100) | spurious_vector;
    const cpu = get_current_thread().cpu orelse @panic("cannot get cpu");
    log.debug("Local storage: 0x{x}", .{@ptrToInt(cpu)});
    // TODO: x2APIC
    const ia32_apic = IA32_APIC_BASE.read();
    const apic_physical_address = get_apic_base(ia32_apic);
    log.debug("APIC physical address: 0x{x}", .{apic_physical_address});
    common.runtime_assert(@src(), apic_physical_address != 0);
    const old_lapic_id = cpu.lapic.id;
    cpu.lapic = LAPIC.new(virtual_address_space, PhysicalAddress.new(apic_physical_address), old_lapic_id);
    cpu.lapic.write(.SPURIOUS, spurious_value);
    // TODO: getting the lapic id from a LAPIC register is not reporting good ids. Why?
    //const lapic_id = cpu.lapic.read(.LAPIC_ID);
    //log.debug("Old LAPIC id: {}. New LAPIC id: {}", .{ old_lapic_id, lapic_id });
    //common.runtime_assert(@src(), lapic_id == cpu.lapic.id);
    log.debug("APIC enabled", .{});
}

var times_mapped: u64 = 0;
pub fn map_lapic(virtual_address_space: *common.VirtualAddressSpace) void {
    if (times_mapped != 0) @panic("called more than once");
    defer times_mapped += 1;

    const cpu = get_current_thread().cpu orelse @panic("wtf");
    common.runtime_assert(@src(), cpu.id == 0);
    common.runtime_assert(@src(), cpu.is_bootstrap);

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

    common.runtime_assert(@src(), !cr0.get_bit(.CD));
    common.runtime_assert(@src(), !cr0.get_bit(.NW));
}

pub fn cpu_start(virtual_address_space: *common.VirtualAddressSpace) void {
    const current_thread = get_current_thread();
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

pub const IOPort = struct {
    pub const DMA1 = 0x0000;
    pub const PIC1 = 0x0020;
    pub const Cyrix_MSR = 0x0022;
    pub const PIT_data = 0x0040;
    pub const PIT_command = 0x0043;
    pub const PS2 = 0x0060;
    pub const CMOS_RTC = 0x0070;
    pub const DMA_page_registers = 0x0080;
    pub const A20 = 0x0092;
    pub const PIC2 = 0x00a0;
    pub const DMA2 = 0x00c0;
    pub const E9_hack = 0x00e9;
    pub const ATA2 = 0x0170;
    pub const ATA1 = 0x01f0;
    pub const parallel_port = 0x0278;
    pub const serial2 = 0x02f8;
    pub const IBM_VGA = 0x03b0;
    pub const floppy = 0x03f0;
    pub const serial1 = 0x03f8;
    pub const PCI_config = 0x0cf8;
    pub const PCI_data = 0x0cfc;
};

const Serial = struct {
    const io_ports = [8]u16{
        0x3F8,
        0x2F8,
        0x3E8,
        0x2E8,
        0x5F8,
        0x4F8,
        0x5E8,
        0x4E8,
    };

    var initialization_state = [1]bool{false} ** 8;

    const InitError = error{
        already_initialized,
        not_present,
    };

    fn Port(comptime port_number: u8) type {
        comptime common.comptime_assert(@src(), port_number > 0 and port_number <= 8);
        const port_index = port_number - 1;

        return struct {
            const io_port = io_ports[port_index];

            fn init() Serial.InitError!void {
                if (initialization_state[port_index]) return Serial.InitError.already_initialized;

                io_write(u8, io_port + 7, 0);
                if (io_read(u8, io_port + 7) != 0) return Serial.InitError.not_present;
                io_write(u8, io_port + 7, 0xff);
                if (io_read(u8, io_port + 7) != 0xff) return Serial.InitError.not_present;
                TODO();
            }
        };
    }
};

pub inline fn io_read(comptime T: type, port: u16) T {
    return switch (T) {
        u8 => asm volatile ("inb %[port], %[result]"
            : [result] "={al}" (-> u8),
            : [port] "N{dx}" (port),
        ),
        u16 => asm volatile ("inw %[port], %[result]"
            : [result] "={ax}" (-> u16),
            : [port] "N{dx}" (port),
        ),
        u32 => asm volatile ("inl %[port], %[result]"
            : [result] "={eax}" (-> u32),
            : [port] "N{dx}" (port),
        ),

        else => unreachable,
    };
}

pub inline fn io_write(comptime T: type, port: u16, value: T) void {
    switch (T) {
        u8 => asm volatile ("outb %[value], %[port]"
            :
            : [value] "{al}" (value),
              [port] "N{dx}" (port),
        ),
        u16 => asm volatile ("outw %[value], %[port]"
            :
            : [value] "{ax}" (value),
              [port] "N{dx}" (port),
        ),
        u32 => asm volatile ("outl %[value], %[port]"
            :
            : [value] "{eax}" (value),
              [port] "N{dx}" (port),
        ),
        else => unreachable,
    }
}

pub inline fn writer_function(str: []const u8) usize {
    for (str) |c| {
        io_write(u8, IOPort.E9_hack, c);
    }

    return str.len;
}

pub const rax = SimpleR64("rax");
pub const rbx = SimpleR64("rbx");
pub const rcx = SimpleR64("rcx");
pub const rdx = SimpleR64("rdx");
pub const rbp = SimpleR64("rbp");
pub const rsp = SimpleR64("rsp");
pub const rsi = SimpleR64("rsi");
pub const rdi = SimpleR64("rdi");
pub const r8 = SimpleR64("r8");
pub const r9 = SimpleR64("r9");
pub const r10 = SimpleR64("r10");
pub const r11 = SimpleR64("r11");
pub const r12 = SimpleR64("r12");
pub const r13 = SimpleR64("r13");
pub const r14 = SimpleR64("r14");
pub const r15 = SimpleR64("r15");

pub const gs = SimpleR64("gs");
pub const cs = SimpleR64("cs");

pub const dr0 = SimpleR64("dr0");
pub const dr1 = SimpleR64("dr1");
pub const dr2 = SimpleR64("dr2");
pub const dr3 = SimpleR64("dr3");
pub const dr4 = SimpleR64("dr4");
pub const dr5 = SimpleR64("dr5");
pub const dr6 = SimpleR64("dr6");
pub const dr7 = SimpleR64("dr7");

pub fn SimpleR64(comptime name: []const u8) type {
    return struct {
        pub inline fn read() u64 {
            return asm volatile ("mov %%" ++ name ++ ", %[result]"
                : [result] "=r" (-> u64),
            );
        }

        pub inline fn write(value: u64) void {
            asm volatile ("mov %[in], %%" ++ name
                :
                : [in] "r" (value),
            );
        }
    };
}

pub fn ComplexR64(comptime name: []const u8, comptime _BitEnum: type) type {
    return struct {
        const BitEnum = _BitEnum;
        pub inline fn read_raw() u64 {
            return asm volatile ("mov %%" ++ name ++ ", %[result]"
                : [result] "=r" (-> u64),
            );
        }

        pub inline fn write_raw(value: u64) void {
            asm volatile ("mov %[in], %%" ++ name
                :
                : [in] "r" (value),
            );
        }

        pub inline fn read() Value {
            return Value{
                .value = read_raw(),
            };
        }

        pub inline fn write(value: Value) void {
            write_raw(value.value);
        }

        pub inline fn get_bit(comptime bit: BitEnum) bool {
            return read().get_bit(bit);
        }

        pub inline fn set_bit(comptime bit: BitEnum) void {
            var value = read();
            value.set_bit(bit);
            write(value);
        }

        pub inline fn clear_bit(comptime bit: BitEnum) void {
            var value = read();
            value.clear_bit(bit);
            write(value);
        }

        pub const Value = struct {
            value: u64,

            pub inline fn get_bit(value: Value, comptime bit: BitEnum) bool {
                return value.value & (1 << @enumToInt(bit)) != 0;
            }

            pub inline fn set_bit(value: *Value, comptime bit: BitEnum) void {
                value.value |= 1 << @enumToInt(bit);
            }

            pub inline fn clear_bit(value: *Value, comptime bit: BitEnum) void {
                const mask = ~(1 << @enumToInt(bit));
                value.value &= mask;
            }
        };
    };
}

// From Intel manual, volume 3, chapter 2.5: Control Registers

/// Contains system control flags that control operating mode and states of the processor.
const cr0 = ComplexR64("cr0", enum(u6) {
    /// Protection Enable (bit 0 of CR0) — Enables protected mode when set; enables real-address mode when
    /// clear. This flag does not enable paging directly. It only enables segment-level protection. To enable paging,
    /// both the PE and PG flags must be set.
    /// See also: Section 9.9, “Mode Switching.”
    PE = 0,

    /// Monitor Coprocessor (bit 1 of CR0) — Controls the interaction of the WAIT (or FWAIT) instruction with
    /// the TS flag (bit 3 of CR0). If the MP flag is set, a WAIT instruction generates a device-not-available exception
    /// (#NM) if the TS flag is also set. If the MP flag is clear, the WAIT instruction ignores the setting of the TS flag.
    /// Table 9-3 shows the recommended setting of this flag, depending on the IA-32 processor and x87 FPU or
    /// math coprocessor present in the system. Table 2-2 shows the interaction of the MP, EM, and TS flags.
    MP = 1,

    /// Emulation (bit 2 of CR0) — Indicates that the processor does not have an internal or external x87 FPU when set;
    /// indicates an x87 FPU is present when clear. This flag also affects the execution of
    /// MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instructions.
    /// When the EM flag is set, execution of an x87 FPU instruction generates a device-not-available exception
    /// (#NM). This flag must be set when the processor does not have an internal x87 FPU or is not connected to
    /// an external math coprocessor. Setting this flag forces all floating-point instructions to be handled by soft-
    /// ware emulation. Table 9-3 shows the recommended setting of this flag, depending on the IA-32 processor
    /// and x87 FPU or math coprocessor present in the system. Table 2-2 shows the interaction of the EM, MP, and
    /// TS flags.
    /// Also, when the EM flag is set, execution of an MMX instruction causes an invalid-opcode exception (#UD)
    /// to be generated (see Table 12-1). Thus, if an IA-32 or Intel 64 processor incorporates MMX technology, the
    /// EM flag must be set to 0 to enable execution of MMX instructions.
    /// Similarly for SSE/SSE2/SSE3/SSSE3/SSE4 extensions, when the EM flag is set, execution of most
    /// SSE/SSE2/SSE3/SSSE3/SSE4 instructions causes an invalid opcode exception (#UD) to be generated (see
    /// Table 13-1). If an IA-32 or Intel 64 processor incorporates the SSE/SSE2/SSE3/SSSE3/SSE4 extensions,
    /// the EM flag must be set to 0 to enable execution of these extensions. SSE/SSE2/SSE3/SSSE3/SSE4
    /// instructions not affected by the EM flag include: PAUSE, PREFETCHh, SFENCE, LFENCE, MFENCE, MOVNTI,
    /// CLFLUSH, CRC32, and POPCNT.
    EM = 2,

    /// Task Switched (bit 3 of CR0) — Allows the saving of the x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4
    /// context on a task switch to be delayed until an x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction is
    /// actually executed by the new task. The processor sets this flag on every task switch and tests it when
    /// executing x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instructions.
    /// * If the TS flag is set and the EM flag (bit 2 of CR0) is clear, a device-not-available exception (#NM) is
    /// raised prior to the execution of any x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction; with the
    /// exception of PAUSE, PREFETCHh, SFENCE, LFENCE, MFENCE, MOVNTI, CLFLUSH, CRC32, and POPCNT.
    /// See the paragraph below for the special case of the WAIT/FWAIT instructions.
    /// * If the TS flag is set and the MP flag (bit 1 of CR0) and EM flag are clear, an #NM exception is not raised
    /// prior to the execution of an x87 FPU WAIT/FWAIT instruction.
    /// * If the EM flag is set, the setting of the TS flag has no effect on the execution of x87
    /// FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instructions.
    /// Table 2-2 shows the actions taken when the processor encounters an x87 FPU instruction based on the
    /// settings of the TS, EM, and MP flags. Table 12-1 and 13-1 show the actions taken when the processor
    /// encounters an MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction.
    /// The processor does not automatically save the context of the x87 FPU, XMM, and MXCSR registers on a
    /// task switch. Instead, it sets the TS flag, which causes the processor to raise an #NM exception whenever it
    /// encounters an x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction in the instruction stream for the
    /// new task (with the exception of the instructions listed above).
    /// The fault handler for the #NM exception can then be used to clear the TS flag (with the CLTS instruction)
    /// and save the context of the x87 FPU, XMM, and MXCSR registers. If the task never encounters an x87
    /// FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction, the x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4
    /// context is never saved.
    TS = 3,

    /// Extension Type (bit 4 of CR0) — Reserved in the Pentium 4, Intel Xeon, P6 family, and Pentium proces-
    /// sors. In the Pentium 4, Intel Xeon, and P6 family processors, this flag is hardcoded to 1. In the Intel386
    /// and Intel486 processors, this flag indicates support of Intel 387 DX math coprocessor instructions when
    /// set.
    ET = 4,

    /// Numeric Error (bit 5 of CR0) — Enables the native (internal) mechanism for reporting x87 FPU errors
    /// when set; enables the PC-style x87 FPU error reporting mechanism when clear. When the NE flag is clear
    /// and the IGNNE# input is asserted, x87 FPU errors are ignored. When the NE flag is clear and the IGNNE#
    /// input is deasserted, an unmasked x87 FPU error causes the processor to assert the FERR# pin to generate
    /// an external interrupt and to stop instruction execution immediately before executing the next waiting
    /// floating-point instruction or WAIT/FWAIT instruction.
    /// The FERR# pin is intended to drive an input to an external interrupt controller (the FERR# pin emulates the
    /// ERROR# pin of the Intel 287 and Intel 387 DX math coprocessors). The NE flag, IGNNE# pin, and FERR#
    /// pin are used with external logic to implement PC-style error reporting. Using FERR# and IGNNE# to handle
    /// floating-point exceptions is deprecated by modern operating systems; this non-native approach also limits
    /// newer processors to operate with one logical processor active.
    /// See also: Section 8.7, “Handling x87 FPU Exceptions in Software” in Chapter 8, “Programming with the x87
    /// FPU,” and Appendix A, “EFLAGS Cross-Reference,” in the Intel® 64 and IA-32 Architectures Software
    /// Developer’s Manual, Volume 1.
    NE = 5,

    /// Write Protect (bit 16 of CR0) — When set, inhibits supervisor-level procedures from writing into read-
    /// only pages; when clear, allows supervisor-level procedures to write into read-only pages (regardless of the
    /// U/S bit setting; see Section 4.1.3 and Section 4.6). This flag facilitates implementation of the copy-on-
    /// write method of creating a new process (forking) used by operating systems such as UNIX. This flag must
    /// be set before software can set CR4.CET, and it cannot be cleared as long as CR4.CET = 1 (see below).
    WP = 16,

    /// Alignment Mask (bit 18 of CR0) — Enables automatic alignment checking when set; disables alignment
    /// checking when clear. Alignment checking is performed only when the AM flag is set, the AC flag in the
    /// EFLAGS register is set, CPL is 3, and the processor is operating in either protected or virtual-8086 mode
    AM = 18,

    /// Not Write-through (bit 29 of CR0) — When the NW and CD flags are clear, write-back (for Pentium 4,
    /// Intel Xeon, P6 family, and Pentium processors) or write-through (for Intel486 processors) is enabled for
    /// writes that hit the cache and invalidation cycles are enabled. See Table 11-5 for detailed information about
    /// the effect of the NW flag on caching for other settings of the CD and NW flags.
    NW = 29,

    /// Cache Disable (bit 30 of CR0) — When the CD and NW flags are clear, caching of memory locations for
    /// the whole of physical memory in the processor’s internal (and external) caches is enabled. When the CD
    /// flag is set, caching is restricted as described in Table 11-5. To prevent the processor from accessing and
    /// updating its caches, the CD flag must be set and the caches must be invalidated so that no cache hits can
    /// occur.
    /// See also: Section 11.5.3, “Preventing Caching,” and Section 11.5, “Cache Control.”
    CD = 30,

    /// Paging (bit 31 of CR0) — Enables paging when set; disables paging when clear. When paging is
    /// disabled, all linear addresses are treated as physical addresses. The PG flag has no effect if the PE flag (bit
    /// 0 of register CR0) is not also set; setting the PG flag when the PE flag is clear causes a general-protection
    /// exception (#GP). See also: Chapter 4, “Paging.”
    /// On Intel 64 processors, enabling and disabling IA-32e mode operation also requires modifying CR0.PG.
    PG = 31,
});
// RESERVED: const CR1 = R64("cr1");

/// Contains the page-fault linear address (the linear address that caused a page fault).
pub const cr2 = SimpleR64("cr2");

/// Contains the physical address of the base of the paging-structure hierarchy and two flags (PCD and
/// PWT). Only the most-significant bits (less the lower 12 bits) of the base address are specified; the lower 12 bits
/// of the address are assumed to be 0. The first paging structure must thus be aligned to a page (4-KByte)
/// boundary. The PCD and PWT flags control caching of that paging structure in the processor’s internal data
/// caches (they do not control TLB caching of page-directory information).
/// When using the physical address extension, the CR3 register contains the base address of the page-directory-
/// pointer table. With 4-level paging and 5-level paging, the CR3 register contains the base address of the PML4
/// table and PML5 table, respectively. If PCIDs are enabled, CR3 has a format different from that illustrated in
/// Figure 2-7. See Section 4.5, “4-Level Paging and 5-Level Paging.”
/// See also: Chapter 4, “Paging.”
pub const cr3 = ComplexR64("cr3", enum(u6) {
    /// Page-level Write-Through (bit 3 of CR3) — Controls the memory type used to access the first paging
    /// structure of the current paging-structure hierarchy. See Section 4.9, “Paging and Memory Typing”. This bit
    /// is not used if paging is disabled, with PAE paging, or with 4-level paging or 5-level paging if CR4.PCIDE=1.
    PWT = 3,

    /// Page-level Cache Disable (bit 4 of CR3) — Controls the memory type used to access the first paging
    /// structure of the current paging-structure hierarchy. See Section 4.9, “Paging and Memory Typing”. This bit
    /// is not used if paging is disabled, with PAE paging, or with 4-level paging1 or 5-level paging if CR4.PCIDE=1.
    PCD = 4,

    PCID_top_bit = 11,
});

/// Contains a group of flags that enable several architectural extensions, and indicate operating system or
/// executive support for specific processor capabilities. Bits CR4[63:32] can only be used for IA-32e mode only
/// features that are enabled after entering 64-bit mode. Bits CR4[63:32] do not have any effect outside of IA-32e
/// mode.
const cr4 = ComplexR64("cr4", enum(u6) {
    /// Virtual-8086 Mode Extensions (bit 0 of CR4) — Enables interrupt- and exception-handling extensions
    /// in virtual-8086 mode when set; disables the extensions when clear. Use of the virtual mode extensions can
    /// improve the performance of virtual-8086 applications by eliminating the overhead of calling the virtual-
    /// 8086 monitor to handle interrupts and exceptions that occur while executing an 8086 program and,
    /// instead, redirecting the interrupts and exceptions back to the 8086 program’s handlers. It also provides
    /// hardware support for a virtual interrupt flag (VIF) to improve reliability of running 8086 programs in multi-
    /// tasking and multiple-processor environments.
    /// See also: Section 20.3, “Interrupt and Exception Handling in Virtual-8086 Mode.”
    VME = 0,

    /// Protected-Mode Virtual Interrupts (bit 1 of CR4) — Enables hardware support for a virtual interrupt
    /// flag (VIF) in protected mode when set; disables the VIF flag in protected mode when clear.
    /// See also: Section 20.4, “Protected-Mode Virtual Interrupts.”
    PVI = 1,

    /// Time Stamp Disable (bit 2 of CR4) — Restricts the execution of the RDTSC instruction to procedures
    /// running at privilege level 0 when set; allows RDTSC instruction to be executed at any privilege level when
    /// clear. This bit also applies to the RDTSCP instruction if supported (if CPUID.80000001H:EDX[27] = 1).
    TSD = 2,

    /// Debugging Extensions (bit 3 of CR4) — References to debug registers DR4 and DR5 cause an unde-
    /// fined opcode (#UD) exception to be generated when set; when clear, processor aliases references to regis-
    /// ters DR4 and DR5 for compatibility with software written to run on earlier IA-32 processors.
    /// See also: Section 17.2.2, “Debug Registers DR4 and DR5.”
    DE = 3,

    /// Page Size Extensions (bit 4 of CR4) — Enables 4-MByte pages with 32-bit paging when set; restricts
    /// 32-bit paging to pages of 4 KBytes when clear.
    /// See also: Section 4.3, “32-Bit Paging.”
    PSE = 4,

    /// Physical Address Extension (bit 5 of CR4) — When set, enables paging to produce physical addresses
    /// with more than 32 bits. When clear, restricts physical addresses to 32 bits. PAE must be set before entering
    /// IA-32e mode.
    /// See also: Chapter 4, “Paging.”
    PAE = 5,

    /// Machine-Check Enable (bit 6 of CR4) — Enables the machine-check exception when set; disables the
    /// machine-check exception when clear.
    /// See also: Chapter 15, “Machine-Check Architecture.”
    MCE = 6,

    /// Page Global Enable (bit 7 of CR4) — (Introduced in the P6 family processors.) Enables the global page
    /// feature when set; disables the global page feature when clear. The global page feature allows frequently
    /// used or shared pages to be marked as global to all users (done with the global flag, bit 8, in a page-direc-
    /// tory-pointer-table entry, a page-directory entry, or a page-table entry). Global pages are not flushed from
    /// the translation-lookaside buffer (TLB) on a task switch or a write to register CR3.
    /// When enabling the global page feature, paging must be enabled (by setting the PG flag in control register
    /// CR0) before the PGE flag is set. Reversing this sequence may affect program correctness, and processor
    /// performance will be impacted.
    /// See also: Section 4.10, “Caching Translation Information.”
    PGE = 7,

    /// Performance-Monitoring Counter Enable (bit 8 of CR4) — Enables execution of the RDPMC instruc-
    /// tion for programs or procedures running at any protection level when set; RDPMC instruction can be
    /// executed only at protection level 0 when clear.
    PME = 8,

    /// Operating System Support for FXSAVE and FXRSTOR instructions (bit 9 of CR4) — When set, this
    /// flag: (1) indicates to software that the operating system supports the use of the FXSAVE and FXRSTOR
    /// instructions, (2) enables the FXSAVE and FXRSTOR instructions to save and restore the contents of the
    /// XMM and MXCSR registers along with the contents of the x87 FPU and MMX registers, and (3) enables the
    /// processor to execute SSE/SSE2/SSE3/SSSE3/SSE4 instructions, with the exception of the PAUSE,
    /// PREFETCHh, SFENCE, LFENCE, MFENCE, MOVNTI, CLFLUSH, CRC32, and POPCNT.
    /// If this flag is clear, the FXSAVE and FXRSTOR instructions will save and restore the contents of the x87 FPU
    /// and MMX registers, but they may not save and restore the contents of the XMM and MXCSR registers. Also,
    /// the processor will generate an invalid opcode exception (#UD) if it attempts to execute any
    /// SSE/SSE2/SSE3 instruction, with the exception of PAUSE, PREFETCHh, SFENCE, LFENCE, MFENCE,
    /// MOVNTI, CLFLUSH, CRC32, and POPCNT. The operating system or executive must explicitly set this flag.
    /// NOTE
    /// CPUID feature flag FXSR indicates availability of the FXSAVE/FXRSTOR instructions. The OSFXSR
    /// bit provides operating system software with a means of enabling FXSAVE/FXRSTOR to save/restore
    /// the contents of the X87 FPU, XMM and MXCSR registers. Consequently OSFXSR bit indicates that
    /// the operating system provides context switch support for SSE/SSE2/SSE3/SSSE3/SSE4.
    OSFXSR = 9,

    /// Operating System Support for Unmasked SIMD Floating-Point Exceptions (bit 10 of CR4) —
    /// When set, indicates that the operating system supports the handling of unmasked SIMD floating-point
    /// exceptions through an exception handler that is invoked when a SIMD floating-point exception (#XM) is
    /// generated. SIMD floating-point exceptions are only generated by SSE/SSE2/SSE3/SSE4.1 SIMD floating-
    /// point instructions.
    /// The operating system or executive must explicitly set this flag. If this flag is not set, the processor will
    /// generate an invalid opcode exception (#UD) whenever it detects an unmasked SIMD floating-point excep-
    /// tion.
    OSXMMEXCPT = 10,

    /// User-Mode Instruction Prevention (bit 11 of CR4) — When set, the following instructions cannot be
    /// executed if CPL > 0: SGDT, SIDT, SLDT, SMSW, and STR. An attempt at such execution causes a general-
    /// protection exception (#GP).
    UMIP = 11,

    /// 57-bit linear addresses (bit 12 of CR4) — When set in IA-32e mode, the processor uses 5-level paging
    /// to translate 57-bit linear addresses. When clear in IA-32e mode, the processor uses 4-level paging to
    /// translate 48-bit linear addresses. This bit cannot be modified in IA-32e mode.
    LA57 = 12,

    /// VMX-Enable Bit (bit 13 of CR4) — Enables VMX operation when set. See Chapter 23, “Introduction to
    /// Virtual Machine Extensions.”
    VMXE = 13,

    /// SMX-Enable Bit (bit 14 of CR4) — Enables SMX operation when set. See Chapter 6, “Safer Mode Exten-
    /// sions Reference” of Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 2D.
    SMXE = 14,

    /// FSGSBASE-Enable Bit (bit 16 of CR4) — Enables the instructions RDFSBASE, RDGSBASE, WRFSBASE,
    /// and WRGSBASE.
    FSGSBASE = 16,

    /// PCID-Enable Bit (bit 17 of CR4) — Enables process-context identifiers (PCIDs) when set. See Section
    /// 4.10.1, “Process-Context Identifiers (PCIDs)”. Applies only in IA-32e mode (if IA32_EFER.LMA = 1).
    PCIDE = 17,

    /// XSAVE and Processor Extended States-Enable Bit (bit 18 of CR4) — When set, this flag: (1) indi-
    /// cates (via CPUID.01H:ECX.OSXSAVE[bit 27]) that the operating system supports the use of the XGETBV,
    /// XSAVE and XRSTOR instructions by general software; (2) enables the XSAVE and XRSTOR instructions to
    /// save and restore the x87 FPU state (including MMX registers), the SSE state (XMM registers and MXCSR),
    /// along with other processor extended states enabled in XCR0; (3) enables the processor to execute XGETBV
    /// and XSETBV instructions in order to read and write XCR0. See Section 2.6 and Chapter 13, “System
    /// Programming for Instruction Set Extensions and Processor Extended States”.
    OSXSAVE = 18,

    /// Key-Locker-Enable Bit (bit 19 of CR4) — When set, the LOADIWKEY instruction is enabled; in addition,
    /// if support for the AES Key Locker instructions has been activated by system firmware,
    /// CPUID.19H:EBX.AESKLE[bit 0] is enumerated as 1 and the AES Key Locker instructions are enabled.1
    /// When clear, CPUID.19H:EBX.AESKLE[bit 0] is enumerated as 0 and execution of any Key Locker instruction
    /// causes an invalid-opcode exception (#UD).
    KL = 19,

    /// SMEP-Enable Bit (bit 20 of CR4) — Enables supervisor-mode execution prevention (SMEP) when set.
    /// See Section 4.6, “Access Rights”.
    SMEP = 20,

    /// SMAP-Enable Bit (bit 21 of CR4) — Enables supervisor-mode access prevention (SMAP) when set. See
    /// Section 4.6, “Access Rights.”
    SMAP = 21,

    /// Enable protection keys for user-mode pages (bit 22 of CR4) — 4-level paging and 5-level paging
    /// associate each user-mode linear address with a protection key. When set, this flag indicates (via
    /// CPUID.(EAX=07H,ECX=0H):ECX.OSPKE [bit 4]) that the operating system supports use of the PKRU
    /// register to specify, for each protection key, whether user-mode linear addresses with that protection key
    /// can be read or written. This bit also enables access to the PKRU register using the RDPKRU and WRPKRU
    /// instructions.
    PKE = 22,

    /// Control-flow Enforcement Technology (bit 23 of CR4) — Enables control-flow enforcement tech-
    /// nology when set. See Chapter 18, “Control-flow Enforcement Technology (CET)” of the IA-32 Intel® Archi-
    /// tecture Software Developer’s Manual, Volume 1. This flag can be set only if CR0.WP is set, and it must be
    /// clear before CR0.WP can be cleared (see below).
    CET = 23,

    /// Enable protection keys for supervisor-mode pages (bit 24 of CR4) — 4-level paging and 5-level
    /// paging associate each supervisor-mode linear address with a protection key. When set, this flag allows use
    /// of the IA32_PKRS MSR to specify, for each protection key, whether supervisor-mode linear addresses with
    /// that protection key can be read or written.
    PKS = 24,
});

/// Provides read and write access to the Task Priority Register (TPR). It specifies the priority threshold
/// value that operating systems use to control the priority class of external interrupts allowed to interrupt the
/// processor. This register is available only in 64-bit mode. However, interrupt filtering continues to apply in
/// compatibility mode.
const cr8 = SimpleR64("cr8");
fn get_task_priority_level() u4 {
    return @truncate(u4, cr8.read());
}

pub const CPUFeatures = struct {
    page_size: u64,
    physical_address_max_bit: u6,
};

pub fn get_physical_address_memory_configuration() void {
    context.max_physical_address_bit = CPUID.get_max_physical_address_bit();
}

pub fn SimpleMSR(comptime msr: u32) type {
    return struct {
        pub inline fn read() u64 {
            var low: u32 = undefined;
            var high: u32 = undefined;

            asm volatile ("rdmsr"
                : [_] "={eax}" (low),
                  [_] "={edx}" (high),
                : [_] "{ecx}" (msr),
            );
            return (@as(u64, high) << 32) | low;
        }

        pub inline fn write(value: u64) void {
            const low = @truncate(u32, value);
            const high = @truncate(u32, value >> 32);

            asm volatile ("wrmsr"
                :
                : [_] "{eax}" (low),
                  [_] "{edx}" (high),
                  [_] "{ecx}" (msr),
            );
        }
    };
}

pub fn ComplexMSR(comptime msr: u32, comptime _BitEnum: type) type {
    return struct {
        pub const BitEnum = _BitEnum;

        pub const Flags = common.Bitflag(false, u64, BitEnum);
        pub inline fn read() Flags {
            var low: u32 = undefined;
            var high: u32 = undefined;

            asm volatile ("rdmsr"
                : [_] "={eax}" (low),
                  [_] "={edx}" (high),
                : [_] "{ecx}" (msr),
            );
            return Flags.from_bits((@as(u64, high) << 32) | low);
        }

        pub inline fn write(flags: Flags) void {
            const value = flags.bits;
            const low = @truncate(u32, value);
            const high = @truncate(u32, value >> 32);

            asm volatile ("wrmsr"
                :
                : [_] "{eax}" (low),
                  [_] "{edx}" (high),
                  [_] "{ecx}" (msr),
            );
        }
    };
}

//pub const PAT = SimpleMSR(0x277);
pub const IA32_STAR = SimpleMSR(0xC0000081);
pub const IA32_LSTAR = SimpleMSR(0xC0000082);
pub const IA32_FMASK = SimpleMSR(0xC0000084);
pub const IA32_FS_BASE = SimpleMSR(0xC0000100);
pub const IA32_GS_BASE = SimpleMSR(0xC0000101);
pub const IA32_KERNEL_GS_BASE = SimpleMSR(0xC0000102);
pub const IA32_EFER = ComplexMSR(0xC0000080, enum(u6) {
    /// Syscall Enable - syscall, sysret
    SCE = 0,
    /// Long Mode Enable
    LME = 8,
    /// Long Mode Active
    LMA = 10,
    /// Enables page access restriction by preventing instruction fetches from PAE pages with the XD bit set
    NXE = 11,
    SVME = 12,
    LMSLE = 13,
    FFXSR = 14,
    TCE = 15,
});
pub const IA32_APIC_BASE = ComplexMSR(0x0000001B, enum(u6) {
    bsp = 8,
    global_enable = 11,
});

fn get_apic_base(ia32_apic_base: IA32_APIC_BASE.Flags) u32 {
    return @truncate(u32, ia32_apic_base.bits & 0xfffff000);
}

pub const RFLAGS = struct {
    pub const Flags = common.Bitflag(false, u64, enum(u6) {
        CF = 0,
        PF = 2,
        AF = 4,
        ZF = 6,
        SF = 7,
        TF = 8,
        IF = 9,
        DF = 10,
        OF = 11,
        IOPL0 = 12,
        IOPL1 = 13,
        NT = 14,
        RF = 16,
        VM = 17,
        AC = 18,
        VIF = 19,
        VIP = 20,
        ID = 21,
    });

    pub inline fn read() Flags {
        return Flags{
            .bits = asm volatile (
                \\pushfq
                \\pop %[flags]
                : [flags] "=r" (-> u64),
            ),
        };
    }
};

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

pub const valid_page_sizes = [3]u64{ 0x1000, 0x1000 * 512, 0x1000 * 512 * 512 };

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

const use_cr8 = true;

pub inline fn enable_interrupts() void {
    if (use_cr8) {
        cr8.write(0);
        asm volatile ("sti");
    } else {
        asm volatile ("sti");
    }
    //log.debug("IF=1", .{});
}

pub inline fn disable_interrupts() void {
    if (use_cr8) {
        cr8.write(0xe);
        asm volatile ("sti");
    } else {
        asm volatile ("cli");
    }
    //log.debug("IF=0", .{});
}

pub inline fn disable_all_interrupts() void {
    asm volatile ("cli");
}

pub inline fn are_interrupts_enabled() bool {
    if (use_cr8) {
        const if_set = RFLAGS.read().contains(.IF);
        const cr8_value = cr8.read();
        return if_set and cr8_value == 0;
    } else {
        const if_set = RFLAGS.read().contains(.IF);
        return if_set;
    }
}

pub const LAPIC = struct {
    // TODO: LAPIC address is shared. Ticks per ms too? Refactor this struct
    address: VirtualAddress,
    ticks_per_ms: u32 = 0,
    id: u32,

    const Register = enum(u32) {
        LAPIC_ID = 0x20,
        EOI = 0xB0,
        SPURIOUS = 0xF0,
        ERROR_STATUS_REGISTER = 0x280,
        ICR_LOW = 0x300,
        ICR_HIGH = 0x310,
        LVT_TIMER = 0x320,
        TIMER_DIV = 0x3E0,
        TIMER_INITCNT = 0x380,
        TIMER_CURRENT_COUNT = 0x390,
    };

    pub inline fn new(virtual_address_space: *common.VirtualAddressSpace, lapic_physical_address: PhysicalAddress, lapic_id: u32) LAPIC {
        //Paging.should_log = true;
        const lapic_virtual_address = lapic_physical_address.to_higher_half_virtual_address();
        log.debug("Virtual address: 0x{x}", .{lapic_virtual_address.value});
        common.runtime_assert(@src(), virtual_address_space.translate_address(lapic_virtual_address) != null);
        log.debug("Checking assert", .{});

        common.runtime_assert(@src(), (virtual_address_space.translate_address(lapic_virtual_address) orelse @panic("Wtfffff")).value == lapic_physical_address.value);
        const lapic = LAPIC{
            .address = lapic_virtual_address,
            .id = lapic_id,
        };
        log.debug("LAPIC initialized: 0x{x}", .{lapic_virtual_address.value});
        return lapic;
    }

    pub inline fn read(lapic: LAPIC, comptime register: LAPIC.Register) u32 {
        const register_index = @enumToInt(register) / @sizeOf(u32);
        const result = lapic.address.access([*]volatile u32)[register_index];
        return result;
    }

    pub inline fn write(lapic: LAPIC, comptime register: Register, value: u32) void {
        const register_index = @enumToInt(register) / @sizeOf(u32);
        lapic.address.access([*]volatile u32)[register_index] = value;
    }

    pub inline fn next_timer(lapic: LAPIC, ms: u32) void {
        common.runtime_assert(@src(), lapic.ticks_per_ms != 0);
        lapic.write(.LVT_TIMER, timer_interrupt | (1 << 17));
        lapic.write(.TIMER_INITCNT, lapic.ticks_per_ms * ms);
    }

    pub inline fn end_of_interrupt(lapic: LAPIC) void {
        log.debug("Signaling end of interrupt", .{});
        lapic.write(.EOI, 0);
    }
};

pub inline fn next_timer(ms: u32) void {
    const current_cpu = get_current_thread().cpu orelse @panic("current cpu not set");
    current_cpu.lapic.next_timer(ms);
}

pub const CPU = struct {
    lapic: LAPIC,
    spinlock_count: u64,
    is_bootstrap: bool,
    id: u32,
    gdt: GDT.Table,
    shared_tss: TSS.Struct,
    idt: IDT,
};

pub fn bootstrap_stacks(cpus: []CPU, virtual_address_space: *common.VirtualAddressSpace, stack_size: u64) void {
    common.runtime_assert(@src(), common.is_aligned(stack_size, context.page_size));
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
    TODO(@src());
    // thread.terminate();
}

fn thread_terminate_stack() callconv(.Naked) void {
    asm volatile (
        \\sub $0x8, %%rsp
        \\jmp thread_terminate
    );
    unreachable;
}

pub const Context = struct {
    cr8: u64,
    ds: u64,
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    rdx: u64,
    rcx: u64,
    rbx: u64,
    rax: u64,
    interrupt_number: u64,
    error_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,

    pub fn new(thread: *common.Thread, entry_point: u64) *Context {
        const kernel_stack = get_kernel_stack(thread);
        const user_stack = get_user_stack(thread);
        const arch_context = from_kernel_stack(kernel_stack);
        thread.kernel_stack = VirtualAddress.new(kernel_stack);
        log.debug("ARch Kernel stack: 0x{x}", .{thread.kernel_stack.value});
        thread.kernel_stack.access(*u64).* = @ptrToInt(thread_terminate_stack);
        // TODO: FPU
        switch (thread.privilege_level) {
            .kernel => {
                arch_context.cs = @offsetOf(GDT.Table, "code_64");
                arch_context.ss = @offsetOf(GDT.Table, "data_64");
                arch_context.ds = @offsetOf(GDT.Table, "data_64");
            },
            .user => {
                arch_context.cs = @offsetOf(GDT.Table, "user_code_64") | 0b11;
                arch_context.ss = @offsetOf(GDT.Table, "user_data") | 0b11;
                arch_context.ds = @offsetOf(GDT.Table, "user_data") | 0b11;
                log.debug("CS: 0x{x}. SS: 0x{x}", .{ arch_context.cs, arch_context.ss });
            },
        }

        arch_context.rflags = RFLAGS.Flags.from_flag(.IF).bits;
        arch_context.rip = entry_point;
        arch_context.rsp = user_stack;
        // TODO: arguments
        arch_context.rdi = 0;

        return arch_context;
    }

    pub fn get_stack_pointer(arch_context: *Context) u64 {
        return arch_context.rsp;
    }

    fn get_kernel_stack(thread: *Thread) u64 {
        return thread.kernel_stack_base.value + thread.kernel_stack_size - 8;
    }

    fn get_user_stack(thread: *Thread) u64 {
        const user_stack_base = if (thread.user_stack_base.value == 0) thread.kernel_stack_base.value else thread.user_stack_base.value;
        const user_stack = thread.user_stack_reserve - 8 + user_stack_base;
        return user_stack;
    }

    fn from_kernel_stack(kernel_stack: u64) *Context {
        return @intToPtr(*Context, kernel_stack - @sizeOf(Context));
    }

    pub fn from_thread(thread: *Thread) *Context {
        return from_kernel_stack(get_kernel_stack(thread));
    }

    pub fn debug(arch_context: *Context) void {
        log.debug("Context address: 0x{x}", .{@ptrToInt(arch_context)});
        inline for (common.fields(Context)) |field| {
            log.debug("{s}: 0x{x}", .{ field.name, @field(arch_context, field.name) });
        }
    }

    pub fn check(arch_context: *Context, src: common.SourceLocation) void {
        var failed = false;
        failed = failed or arch_context.cs > 0x100;
        failed = failed or arch_context.ss > 0x100;
        // TODO: more checking
        if (failed) {
            arch_context.debug();
            kernel.crash("check failed: {s}:{}:{} {s}()", .{ src.file, src.line, src.column, src.fn_name });
        }
    }
};

pub inline fn flush_segments_kernel() void {
    asm volatile (
        \\xor %%rax, %%rax
        \\mov %[data_segment_selector], %%rax
        \\mov %%rax, %%ds
        \\mov %%rax, %%es
        \\mov %%rax, %%fs
        \\mov %%rax, %%gs
        :
        : [data_segment_selector] "i" (@as(u64, @offsetOf(GDT.Table, "data_64"))),
    );
}

var pci_lock: Spinlock = undefined;

inline fn notify_config_op(bus: u8, slot: u8, function: u8, offset: u8) void {
    io_write(u32, IOPort.PCI_config, 0x80000000 | (@as(u32, bus) << 16) | (@as(u32, slot) << 11) | (@as(u32, function) << 8) | offset);
}

pub fn pci_read_config(comptime T: type, bus: u8, slot: u8, function: u8, offset: u8) T {
    const IntType = common.IntType(.unsigned, @bitSizeOf(T));
    comptime common.comptime_assert(IntType == u8 or IntType == u16 or IntType == u32);
    pci_lock.acquire();
    defer pci_lock.release();

    notify_config_op(bus, slot, function, offset);
    const result_int = io_read(IntType, IOPort.PCI_data + @intCast(u16, offset % 4));
    switch (@typeInfo(T)) {
        .Enum => {
            const result = @intToEnum(T, result_int);
            return result;
        },
        else => {
            const result = @bitCast(T, result_int);
            return result;
        },
    }
}

pub fn pci_write_config(comptime T: type, value: T, bus: u8, slot: u8, function: u8, offset: u8) void {
    const IntType = common.IntType(.unsigned, @bitSizeOf(T));
    comptime common.comptime_assert(IntType == u8 or IntType == u16 or IntType == u32);
    pci_lock.acquire();
    defer pci_lock.release();

    common.runtime_assert(@src(), common.is_aligned(offset, 4));
    notify_config_op(bus, slot, function, offset);

    io_write(IntType, IOPort.PCI_data + @intCast(u16, offset % 4), value);
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

pub inline fn switch_context_preamble() void {
    asm volatile ("cli");
}

pub inline fn switch_address_spaces_if_necessary(new_address_space: *common.VirtualAddressSpace) void {
    const current_cr3 = cr3.read_raw();
    if (current_cr3 != new_address_space.arch.cr3) {
        cr3.write_raw(new_address_space.arch.cr3);
    }
}

pub inline fn set_new_stack(new_stack: u64) void {
    asm volatile ("mov %[in], %%rsp"
        :
        : [in] "r" (new_stack),
        : "nostack"
    );
}

pub fn post_context_switch(arch_context: *Context, new_thread: *common.Thread, old_address_space: *common.VirtualAddressSpace) callconv(.C) void {
    log.debug("Context switching", .{});
    if (@import("root").scheduler.lock.were_interrupts_enabled != 0) {
        @panic("interrupts were enabled");
    }
    kernel.scheduler.lock.release();
    //common.runtime_assert(@src(), context == new_thread.context);
    //common.runtime_assert(@src(), context.rsp < new_thread.kernel_stack_base.value + new_thread.kernel_stack_size);
    arch_context.check(@src());
    common.runtime_assert(@src(), new_thread.current_thread == new_thread);
    set_current_thread(new_thread);
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
    if (are_interrupts_enabled()) @panic("interrupts enabled");
    if (cpu.spinlock_count > 0) @panic("spinlocks active");
    // TODO: profiling
    if (should_swap_gs) asm volatile ("swapgs");
}

pub inline fn set_argument(comptime argument_i: comptime_int, argument_value: u64) void {
    const register_name = switch (argument_i) {
        0 => "rdi",
        1 => "rsi",
        2 => "rdx",
        3 => "rcx",
        4 => "r8",
        5 => "r9",
        else => unreachable,
    };
    const register = SimpleR64(register_name);
    register.write(argument_value);
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

pub fn preinit_bsp(scheduler: *Scheduler, virtual_address_space: *common.VirtualAddressSpace, bootstrap_context: *common.BootstrapContext) void {
    // @ZigBug: @ptrCast here crashes the compiler

    bootstrap_context.cpu.id = 0;
    bootstrap_context.thread.cpu = &bootstrap_context.cpu;
    bootstrap_context.thread.context = &bootstrap_context.context;
    bootstrap_context.thread.address_space = virtual_address_space;
    preset_thread_pointer_bsp(&bootstrap_context.thread);
    set_current_thread(&bootstrap_context.thread);

    scheduler.cpus = @intToPtr([*]CPU, @ptrToInt(&bootstrap_context.cpu))[0..1];
}
