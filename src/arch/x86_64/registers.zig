const common = @import("common");
const assert = common.assert;

const privileged = @import("privileged");
const PhysicalAddress = privileged.PhysicalAddress;

const arch = @import("arch");
const x86_64 = arch.x86_64;

pub const IA32_LSTAR = SimpleMSR(0xC0000082);
pub const IA32_FMASK = SimpleMSR(0xC0000084);
pub const IA32_FS_BASE = SimpleMSR(0xC0000100);
pub const IA32_GS_BASE = SimpleMSR(0xC0000101);
pub const IA32_KERNEL_GS_BASE = SimpleMSR(0xC0000102);

pub const MemoryType = enum(u8) {
    uncacheable = 0,
    write_combining = 1,
    reserved0 = 2,
    reserved1 = 3,
    write_through = 4,
    write_protected = 5,
    write_back = 6,
    uncached = 7,
};

pub const IA32_PAT = extern struct {
    page_attributes: [8]MemoryType,

    const MSR = SimpleMSR(0x277);

    pub fn read() IA32_PAT {
        return @bitCast(IA32_PAT, MSR.read());
    }

    pub fn write(pat: IA32_PAT) void {
        MSR.write(@bitCast(u64, pat));
    }
};

pub const IA32_EFER = packed struct(u64) {
    /// Syscall Enable - syscall, sysret
    SCE: bool = false,
    reserved0: u7 = 0,
    /// Long Mode Enable
    LME: bool = false,
    reserved1: bool = false,
    /// Long Mode Active
    LMA: bool = false,
    /// Enables page access restriction by preventing instruction fetches from PAE pages with the XD bit set
    NXE: bool = false,
    SVME: bool = false,
    LMSLE: bool = false,
    FFXSR: bool = false,
    TCE: bool = false,
    reserved2: u48 = 0,

    comptime {
        assert(@sizeOf(u64) == @sizeOf(IA32_EFER));
    }

    pub const MSR = SimpleMSR(0xC0000080);

    pub fn read() IA32_EFER {
        const result = MSR.read();
        const typed_result = @bitCast(IA32_EFER, result);
        return typed_result;
    }

    pub fn write(typed_value: IA32_EFER) void {
        const value = @bitCast(u64, typed_value);
        MSR.write(value);
    }
};

pub const IA32_STAR = packed struct(u64) {
    reserved: u32 = 0,
    kernel_cs: u16 = 0,
    user_cs_anchor: u16 = 0,

    pub const MSR = SimpleMSR(0xC0000081);

    pub fn read() @This() {
        const result = MSR.read();
        const typed_result = @bitCast(@This(), result);
        return typed_result;
    }

    pub fn write(typed_value: @This()) void {
        const value = @bitCast(u64, typed_value);
        MSR.write(value);
    }
};

pub const IA32_APIC_BASE = packed struct(u64) {
    reserved0: u8 = 0,
    bsp: bool = false,
    reserved1: u1 = 0,
    extended: bool = false,
    global_enable: bool = false,
    address: u24,
    reserved2: u28 = 0,

    pub const MSR = SimpleMSR(0x0000001B);

    pub fn read() IA32_APIC_BASE {
        const result = MSR.read();
        const typed_result = @bitCast(IA32_APIC_BASE, result);
        return typed_result;
    }

    pub fn write(typed_value: IA32_APIC_BASE) void {
        const value = @bitCast(u64, typed_value);
        MSR.write(value);
    }

    pub fn get_address(ia32_apic_base: IA32_APIC_BASE) PhysicalAddress {
        return PhysicalAddress.new(@as(u64, ia32_apic_base.address) << @bitOffsetOf(IA32_APIC_BASE, "address"));
    }
};

pub fn get_apic_base() PhysicalAddress {
    return PhysicalAddress.new(@bitCast(u64, IA32_APIC_BASE.read()) & 0x0000_ffff_ffff_f000);
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
