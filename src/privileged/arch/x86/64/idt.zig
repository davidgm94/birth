const IDT = @This();

const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.IDT);
const RFLAGS = lib.arch.x86_64.registers.RFLAGS;
const comptimePrint = lib.comptimePrint;

const privileged = @import("privileged");
const CoreDirectorData = privileged.CoreDirectorData;
const PhysicalAddress = privileged.PhysicalAddress;
const VirtualAddress = privileged.VirtualAddress;

const x86_64 = privileged.arch.x86_64;
const DescriptorTable = x86_64.DescriptorTable;
const GDT = x86_64.GDT;
const registers = x86_64.registers;
const cr2 = registers.cr2;

//const interrupts = x86_64.interrupts;
//const DescriptorTable = x86_64.DescriptorTable;
//const GDT = x86_64.GDT;

pub const exception_count = 32;
pub const entry_count = 256;
var idt: [entry_count]Descriptor align(0x10) = undefined;

const GateType = enum(u4) {
    task = 0x5,
    interrupt = 0xe,
    trap = 0xf,
};


pub fn setup() void {
    for (idt, 0..) |*entry, i| {
        entry.* = IDT.Descriptor.new(&handlers, i);
    }

    const idt_register = DescriptorTable.Register{
        .limit = @sizeOf(@TypeOf(idt)) - 1,
        .address = @ptrToInt(&idt),
    };

    asm volatile (
        \\lidt (%[idt_address])
        \\sti
        :
        : [idt_address] "r" (&idt_register),
    );
}

//pub inline fn prologue() void {
//asm volatile (
//\\cld
//\\push %%rax
//\\push %%rbx
//\\push %%rcx
//\\push %%rdx
//\\push %%rdi
//\\push %%rsi
//\\push %%rbp
//\\push %%r8
//\\push %%r9
//\\push %%r10
//\\push %%r11
//\\push %%r12
//\\push %%r13
//\\push %%r14
//\\push %%r15
//\\xor %%rax, %%rax
//\\mov %%ds, %%rax
//\\push %% rax
//\\mov %%cr8, %%rax
//\\push %%rax
//\\mov %%rsp, %%rdi
//);
//}

//pub inline fn epilogue() void {
//asm volatile (
//\\cli
//\\pop %%rax
//\\mov %%rax, %%cr8
//\\pop %%rax
//\\mov %%rax, %%ds
//\\mov %%rax, %%es
//\\mov %%rax, %%fs
//\\pop %%r15
//\\pop %%r14
//\\pop %%r13
//\\pop %%r12
//\\pop %%r11
//\\pop %%r10
//\\pop %%r9
//\\pop %%r8
//\\pop %%rbp
//\\pop %%rsi
//\\pop %%rdi
//\\pop %%rdx
//\\pop %%rcx
//\\pop %%rbx
//\\pop %%rax
//\\add $0x10, %%rsp
//\\iretq
//);
//}

const Frame = extern struct {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    rsp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: RFLAGS,
    cs: u64,
    ss: u64,

    pub fn format(frame: *const Frame, comptime _: []const u8, _: lib.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try writer.writeAll("\n");
        inline for (lib.fields(Frame)) |field| {
            const name = field.name;
            const value = @field(frame, field.name);
            const args = .{ name, value };

            switch (field.type) {
                u64 => try lib.format(writer, "\t{s}: 0x{x}\n", args),
                RFLAGS => try lib.format(writer, "\t{s}: {}\n", args),
                else => @compileError("Type not supported"),
            }
        }
    }
};

export fn kernel_exception_handler(interrupt_number: u64, error_code: u64, save_frame: *Frame) noreturn {
    log.err("Exception 0x{x} happened with error code 0x{x}.{}", .{ interrupt_number, error_code, save_frame });
    if (interrupt_number == 0xe) {
        //const virtual_address = VirtualAddress(.local).new(cr2.read());
        //_ = virtual_address;
        @panic("PF");
        //panic("Page fault at {}", .{virtual_address});
    } else {
        while (true) {}
    }
}

export fn user_exception_handler() noreturn {
    log.err("User exception happened!", .{});
    while (true) {}
}

export fn irq_handler() noreturn {
    log.err("IRQ to be handled!", .{});
    while (true) {}
}

export fn handle_irq() noreturn {
    log.err("IRQ to be handled!", .{});
    while (true) {}
}


const Exception = enum(u5) {
    divide_by_zero = 0x00,
    debug = 0x01,
    non_maskable_interrupt = 0x2,
    breakpoint = 0x03,
    overflow = 0x04,
    bound_range_exceeded = 0x05,
    invalid_opcode = 0x06,
    device_not_available = 0x07,
    double_fault = 0x08,
    coprocessor_segment_overrun = 0x09,
    invalid_tss = 0x0a,
    segment_not_present = 0x0b,
    stack_segment_fault = 0x0c,
    general_protection_fault = 0x0d,
    page_fault = 0x0e,
    x87_floating_point_exception = 0x10,
    alignment_check = 0x11,
    machine_check = 0x12,
    simd_floating_point_exception = 0x13,
    virtualization_exception = 0x14,
    control_protection_exception = 0x15,
    hypervisor_injection_exception = 0x1c,
    vmm_communication_exception = 0x1d,
    security_exception = 0x1e,
};
//pub fn install_handlers(idt: *IDT) void {
//}

pub const Descriptor = packed struct {
    offset_low: u16,
    segment_selector: u16 = @offsetOf(GDT.Table, "code_64"),
    interrupt_stack_table: u3 = 0,
    reserved: u5 = 0,
    type: GateType = .interrupt,
    reserved1: u1 = 0,
    descriptor_privilege_level: u2,
    present: u1 = 1,
    offset_mid: u16,
    offset_high: u32,
    reserved2: u32 = 0,

    comptime {
        assert(@sizeOf(Descriptor) == 2 * @sizeOf(u64));
    }

    pub fn new(idt_handlers: []const Handler, index: usize) Descriptor {
        const handler = idt_handlers[index];
        const handler_address = @ptrToInt(handler);
        const is_breakpoint_exception = index == 3;
        const descriptor_privilege_level: u2 = (@as(u2, @boolToInt(is_breakpoint_exception)) << 1) | @boolToInt(is_breakpoint_exception);
        return IDT.Descriptor{
            .offset_low = @truncate(u16, handler_address),
            .descriptor_privilege_level = descriptor_privilege_level,
            .offset_mid = @truncate(u16, handler_address >> 16),
            .offset_high = @truncate(u32, handler_address >> 32),
        };
    }
};
