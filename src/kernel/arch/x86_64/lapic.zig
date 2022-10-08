const LAPIC = @This();

const common = @import("common");
const assert = common.assert;
const log = common.log.scoped(.LAPIC);

const RNU = @import("RNU");
const PhysicalAddress = RNU.PhysicalAddress;
const VirtualAddress = RNU.VirtualAddress;
const VirtualAddressSpace = RNU.VirtualAddressSpace;

pub const timer_interrupt = 0x40;

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

pub inline fn new(virtual_address_space: *VirtualAddressSpace, lapic_physical_address: PhysicalAddress, lapic_id: u32) LAPIC {
    const lapic_virtual_address = lapic_physical_address.to_higher_half_virtual_address();
    log.debug("Virtual address: 0x{x}", .{lapic_virtual_address.value});
    assert(virtual_address_space.translate_address(lapic_virtual_address) != null);
    log.debug("Checking assert", .{});

    assert((virtual_address_space.translate_address(lapic_virtual_address) orelse @panic("Wtfffff")).value == lapic_physical_address.value);
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
    assert(lapic.ticks_per_ms != 0);
    lapic.write(.LVT_TIMER, timer_interrupt | (1 << 17));
    lapic.write(.TIMER_INITCNT, lapic.ticks_per_ms * ms);
}

pub fn end_of_interrupt(lapic: LAPIC) void {
    lapic.write(.EOI, 0);
}
