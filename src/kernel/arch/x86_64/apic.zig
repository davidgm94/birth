const common = @import("common");
const log = common.log.scoped(.APIC);

const privileged = @import("privileged");
const VirtualAddress = privileged.VirtualAddress;

const arch = @import("arch");
const IA32_APIC_BASE = arch.x86_64.registers.IA32_APIC_BASE;

const ID = packed struct(u32) {
    reserved: u24,
    apic_id: u8,

    pub fn read(lapic_base: VirtualAddress) ID {
        return lapic_base.offset(@enumToInt(Register.LAPIC_ID)).access(*volatile ID).*;
    }
};

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

pub fn init() void {
    var ia32_apic_base = IA32_APIC_BASE.read();
    const apic_base_physical_address = ia32_apic_base.get_address();
    const apic_base = arch.paging.map_device(apic_base_physical_address, arch.page_size) catch @panic("mapping apic failed");
    log.debug("APIC base: {}", .{apic_base});
    const id_register = ID.read(apic_base);
    const id = id_register.apic_id;
    _ = id;
    const cpuid_result = arch.x86_64.CPUID.cpuid(1);

    // TODO: x2APIC
    if (cpuid_result.ecx & 0b10000_0000_0000_0000_0000 != 0) {
        log.warn("x2apic is supported by the CPU but not implemented!", .{});
    }
    const spurious_vector: u8 = 0xFF;
    apic_base.offset(@enumToInt(Register.SPURIOUS)).access(*volatile u32).* = @as(u32, 0x100) | spurious_vector;

    ia32_apic_base.global_enable = true;
    ia32_apic_base.write();
    log.debug("APIC enabled", .{});

    if (ia32_apic_base.bsp) {
        asm volatile ("cli");
        arch.x86_64.PIC.disable();
        log.debug("PIC disabled!", .{});
    }
}
