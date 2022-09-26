const IDT = @This();

const common = @import("common");
const assert = common.assert;
const log = common.log.scoped(.IDT);

const arch = @import("arch");
const x86_64 = arch.x86_64;

const interrupts = x86_64.interrupts;
const DescriptorTable = x86_64.DescriptorTable;
const GDT = x86_64.GDT;

entries: [entry_count]Descriptor,

pub const entry_count = 256;

pub const Descriptor = packed struct {
    offset_low: u16,
    segment_selector: u16 = @offsetOf(GDT.Table, "code_64"),
    interrupt_stack_table: u3 = 0,
    reserved: u5 = 0,
    type: GateType = .interrupt,
    reserved1: u1 = 0,
    descriptor_privilege_level: u2 = 0,
    present: u1 = 1,
    offset_mid: u16,
    offset_high: u32,
    reserved2: u32 = 0,

    comptime {
        assert(@sizeOf(Descriptor) == 2 * @sizeOf(u64));
    }

    pub fn from_handler(handler: interrupts.Handler) Descriptor {
        const handler_address = @ptrToInt(handler);
        return IDT.Descriptor{
            .offset_low = @truncate(u16, handler_address),
            .offset_mid = @truncate(u16, handler_address >> 16),
            .offset_high = @truncate(u32, handler_address >> 32),
        };
    }
};

const GateType = enum(u4) {
    task = 0x5,
    interrupt = 0xe,
    trap = 0xf,
};

pub inline fn load(table: *IDT) void {
    const idtr = DescriptorTable.Register{
        .limit = @sizeOf(IDT) - 1,
        .address = @ptrToInt(table),
    };

    asm volatile (
        \\lidt (%[idt_address])
        :
        : [idt_address] "r" (&idtr),
    );
}
