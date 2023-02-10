const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.APIC);
const cpuid = lib.arch.x86_64.cpuid;
const maxInt = lib.maxInt;

const privileged = @import("privileged");
const VirtualAddress = privileged.VirtualAddress;

const arch = privileged.arch;
const x86_64 = privileged.arch.x86_64;
const IA32_APIC_BASE = x86_64.registers.IA32_APIC_BASE;
const io = x86_64.io;

const ID = packed struct(u32) {
    reserved: u24,
    apic_id: u8,

    pub fn read(apic_base: VirtualAddress(.global)) ID {
        return apic_base.offset(@enumToInt(Register.id)).access(*volatile ID).*;
    }
};

const TaskPriorityRegister = packed struct(u32) {
    subclass: u4 = 0,
    class: u4 = 0,
    reserved: u24 = 0,

    pub fn write(tpr: TaskPriorityRegister, apic_base: VirtualAddress(.global)) void {
        apic_base.offset(@enumToInt(Register.tpr)).access(*volatile TaskPriorityRegister).* = tpr;
    }
};

const LVTTimer = packed struct(u32) {
    vector: u8 = 0xfa,
    reserved: u4 = 0,
    delivery_status: bool = false,
    reserved1: u3 = 0,
    mask: bool = true,
    mode: Mode = .oneshot,
    reserved2: u13 = 0,

    const Mode = enum(u2) {
        oneshot = 0,
        periodic = 1,
        tsc_deadline = 2,
    };

    fn write(timer: LVTTimer, apic_base: VirtualAddress(.global)) void {
        apic_write(@This(), timer, Register.lvt_timer, apic_base);
    }
};

const DivideConfigurationRegister = packed struct(u32) {
    divide: Divide = .by_1,
    reserved1: u28 = 0,

    // Divide[bit 2] is always 0
    const Divide = enum(u4) {
        by_2 = 0b0000,
        by_4 = 0b0001,
        by_8 = 0b0010,
        by_16 = 0b0011,
        by_32 = 0b1000,
        by_64 = 0b1001,
        by_128 = 0b1010,
        by_1 = 0b1011,
    };

    fn read(apic_base: VirtualAddress(.global)) DivideConfigurationRegister {
        return apic_read(@This(), Register.timer_div, apic_base);
    }

    fn write(dcr: DivideConfigurationRegister, apic_base: VirtualAddress(.global)) void {
        apic_write(@This(), dcr, Register.timer_div, apic_base);
    }

    //fn write(
};

fn apic_read(comptime T: type, register_offset: Register, apic_base: VirtualAddress(.global)) T {
    return apic_base.offset(@enumToInt(register_offset)).access(*volatile T).*;
}

fn apic_write(comptime T: type, register: T, register_offset: Register, apic_base: VirtualAddress(.global)) void {
    apic_base.offset(@enumToInt(register_offset)).access(*volatile T).* = register;
}

const Register = enum(u32) {
    id = 0x20,
    version = 0x30,
    tpr = 0x80,
    apr = 0x90,
    ppr = 0xa0,
    eoi = 0xB0,
    spurious = 0xF0,
    error_status_register = 0x280,
    icr_low = 0x300,
    icr_high = 0x310,
    lvt_timer = 0x320,
    timer_div = 0x3e0,
    timer_initcnt = 0x380,
    timer_current_count = 0x390,
};

pub fn init() VirtualAddress(.global) {
    var ia32_apic_base = IA32_APIC_BASE.read();
    is_bsp = ia32_apic_base.bsp;
    const apic_base_physical_address = ia32_apic_base.get_address();
    comptime {
        assert(lib.arch.valid_page_sizes[0] == 0x1000);
    }
    const apic_base = arch.paging.map_device(apic_base_physical_address, lib.arch.valid_page_sizes[0]) catch @panic("mapping apic failed");
    log.debug("APIC base: {}", .{apic_base});
    const id_register = ID.read(apic_base);
    const id = id_register.apic_id;
    _ = id;
    const cpuid_result = cpuid(1);

    // TODO: x2APIC
    if (cpuid_result.ecx & 0b10000_0000_0000_0000_0000 != 0) {
        log.warn("x2apic is supported by the CPU but not implemented!", .{});
    }
    const spurious_vector: u8 = 0xFF;
    apic_base.offset(@enumToInt(Register.spurious)).access(*volatile u32).* = @as(u32, 0x100) | spurious_vector;

    const tpr = TaskPriorityRegister{};
    tpr.write(apic_base);

    const lvt_timer = LVTTimer{};
    lvt_timer.write(apic_base);

    ia32_apic_base.global_enable = true;
    ia32_apic_base.write();
    log.debug("APIC enabled", .{});

    if (is_bsp) {
        asm volatile ("cli");
        arch.x86_64.PIC.disable();
        log.debug("PIC disabled!", .{});
    }

    return apic_base;
}

const use_tsc_deadline = false;

fn init_timer(apic_base: VirtualAddress, masked: bool, periodic: bool) void {
    var lvt_timer = LVTTimer{};
    lvt_timer.vector = 0xfa;
    lvt_timer.mask = masked;
    lvt_timer.mode = if (periodic) .periodic else if (use_tsc_deadline and !masked) .tsc_deadline else .oneshot;
    lvt_timer.write(apic_base);
}

fn set_divide(apic_base: VirtualAddress, divide: DivideConfigurationRegister.Divide) void {
    var dcr = DivideConfigurationRegister.read(apic_base);
    dcr.divide = divide;
    dcr.write(apic_base);
}

pub fn calibrate_timer_with_rtc(apic_base: VirtualAddress(.global)) void {
    init_timer(apic_base, true, false);
    set_divide(apic_base, .by_1);

    @panic("TODO: calibrate_timer_with_rtc");
}

pub var is_bsp = false;

pub fn calibrate_timer(apic_base: VirtualAddress(.global)) void {
    if (is_bsp) {
        //calibrate_timer_with_rtc(apic_base);
        const timer_calibration_start = read_timestamp();
        var times_i: u64 = 0;
        const times = 8;

        apic_write(u32, lib.maxInt(u32), Register.timer_initcnt, apic_base);

        while (times_i < times) : (times_i += 1) {
            io.write(u8, io.Ports.PIT_command, 0x30);
            io.write(u8, io.Ports.PIT_data, 0xa9);
            io.write(u8, io.Ports.PIT_data, 0x04);

            while (true) {
                io.write(u8, io.Ports.PIT_command, 0xe2);
                if (io.read(u8, io.Ports.PIT_data) & (1 << 7) != 0) break;
            }
        }

        const ticks_per_ms = (maxInt(u32) - apic_read(u32, .timer_current_count, apic_base)) >> 4;
        const timer_calibration_end = read_timestamp();
        const timestamp_ticks_per_ms = (timer_calibration_end - timer_calibration_start) >> 3;
        log.debug("Ticks per ms: {}. Timestamp ticks per ms: {}", .{ ticks_per_ms, timestamp_ticks_per_ms });
    } else {
        @panic("todo calibrate_timer");
    }
}

pub inline fn read_timestamp() u64 {
    var rdx: u64 = undefined;
    var rax: u64 = undefined;

    asm volatile (
        \\rdtsc
        : [rax] "={rax}" (rax),
          [rdx] "={rdx}" (rdx),
    );

    return rdx << 32 | rax;
}
