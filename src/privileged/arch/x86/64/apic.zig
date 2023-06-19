const APIC = @This();

const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.APIC);
const cpuid = lib.arch.x86_64.cpuid;
const maxInt = lib.maxInt;

const privileged = @import("privileged");
const VirtualAddress = privileged.arch.VirtualAddress;

const arch = privileged.arch;
const x86_64 = privileged.arch.x86_64;
const IA32_APIC_BASE = x86_64.registers.IA32_APIC_BASE;
const io = x86_64.io;

const ID = packed struct(u32) {
    reserved: u24,
    apic_id: u8,

    pub inline fn read() ID {
        return APIC.read(.id);
    }
};

pub const TaskPriorityRegister = packed struct(u32) {
    subclass: u4 = 0,
    class: u4 = 0,
    reserved: u24 = 0,

    pub inline fn write(tpr: TaskPriorityRegister) void {
        APIC.write(.tpr, @as(u32, @bitCast(tpr)));
    }
};

pub const LVTTimer = packed struct(u32) {
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

    pub inline fn write(timer: LVTTimer) void {
        APIC.write(.lvt_timer, @as(u32, @bitCast(timer)));
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

    inline fn read() DivideConfigurationRegister {
        return APIC.read(.timer_div);
    }

    inline fn write(dcr: DivideConfigurationRegister) void {
        APIC.write(.timer_div, @as(u32, @bitCast(dcr)));
    }
};

pub inline fn access(register: Register) *volatile u32 {
    const physical_address = IA32_APIC_BASE.read().getAddress();
    const virtual_address = switch (lib.cpu.arch) {
        .x86 => physical_address.toIdentityMappedVirtualAddress(),
        .x86_64 => switch (lib.os) {
            .freestanding => physical_address.toHigherHalfVirtualAddress(),
            .uefi => physical_address.toIdentityMappedVirtualAddress(),
            else => @compileError("Operating system not supported"),
        },
        else => @compileError("Architecture not supported"),
    };

    return virtual_address.offset(@intFromEnum(register)).access(*volatile u32);
}

pub inline fn read(register: Register) u32 {
    return access(register).*;
}

pub inline fn write(register: Register, value: u32) void {
    access(register).* = value;
}

pub const Register = enum(u32) {
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

pub fn calibrateTimer() privileged.arch.x86_64.TicksPerMS {
    //calibrate_timer_with_rtc(apic_base);
    const timer_calibration_start = lib.arch.x86_64.readTimestamp();
    var times_i: u64 = 0;
    const times = 8;

    APIC.write(.timer_initcnt, lib.maxInt(u32));

    while (times_i < times) : (times_i += 1) {
        io.write(u8, io.Ports.PIT_command, 0x30);
        io.write(u8, io.Ports.PIT_data, 0xa9);
        io.write(u8, io.Ports.PIT_data, 0x04);

        while (true) {
            io.write(u8, io.Ports.PIT_command, 0xe2);
            if (io.read(u8, io.Ports.PIT_data) & (1 << 7) != 0) break;
        }
    }

    const ticks_per_ms = (maxInt(u32) - read(.timer_current_count)) >> 4;
    const timer_calibration_end = lib.arch.x86_64.readTimestamp();
    const timestamp_ticks_per_ms = @as(u32, @intCast((timer_calibration_end - timer_calibration_start) >> 3));

    return .{
        .tsc = timestamp_ticks_per_ms,
        .lapic = ticks_per_ms,
    };
}
