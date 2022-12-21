const IDT = @This();

const common = @import("common");
const assert = common.assert;
const log = common.log.scoped(.IDT);
const RFLAGS = common.arch.x86_64.registers.RFLAGS;

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
pub const HandlerPrototype = fn () align(0x10) callconv(.Naked) void;
pub const Handler = *const HandlerPrototype;

pub const handlers = [IDT.entry_count]Handler{
    get_handler(0),
    get_handler(1),
    get_handler(2),
    get_handler(3),
    get_handler(4),
    get_handler(5),
    get_handler(6),
    get_handler(7),
    get_handler(8),
    get_handler(9),
    get_handler(10),
    get_handler(11),
    get_handler(12),
    get_handler(13),
    get_handler(14),
    get_handler(15),
    get_handler(16),
    get_handler(17),
    get_handler(18),
    get_handler(19),
    get_handler(20),
    get_handler(21),
    get_handler(22),
    get_handler(23),
    get_handler(24),
    get_handler(25),
    get_handler(26),
    get_handler(27),
    get_handler(28),
    get_handler(29),
    get_handler(30),
    get_handler(31),
    get_handler(32),
    get_handler(33),
    get_handler(34),
    get_handler(35),
    get_handler(36),
    get_handler(37),
    get_handler(38),
    get_handler(39),
    get_handler(40),
    get_handler(41),
    get_handler(42),
    get_handler(43),
    get_handler(44),
    get_handler(45),
    get_handler(46),
    get_handler(47),
    get_handler(48),
    get_handler(49),
    get_handler(50),
    get_handler(51),
    get_handler(52),
    get_handler(53),
    get_handler(54),
    get_handler(55),
    get_handler(56),
    get_handler(57),
    get_handler(58),
    get_handler(59),
    get_handler(60),
    get_handler(61),
    get_handler(62),
    get_handler(63),
    get_handler(64),
    get_handler(65),
    get_handler(66),
    get_handler(67),
    get_handler(68),
    get_handler(69),
    get_handler(70),
    get_handler(71),
    get_handler(72),
    get_handler(73),
    get_handler(74),
    get_handler(75),
    get_handler(76),
    get_handler(77),
    get_handler(78),
    get_handler(79),
    get_handler(80),
    get_handler(81),
    get_handler(82),
    get_handler(83),
    get_handler(84),
    get_handler(85),
    get_handler(86),
    get_handler(87),
    get_handler(88),
    get_handler(89),
    get_handler(90),
    get_handler(91),
    get_handler(92),
    get_handler(93),
    get_handler(94),
    get_handler(95),
    get_handler(96),
    get_handler(97),
    get_handler(98),
    get_handler(99),

    get_handler(100),
    get_handler(101),
    get_handler(102),
    get_handler(103),
    get_handler(104),
    get_handler(105),
    get_handler(106),
    get_handler(107),
    get_handler(108),
    get_handler(109),
    get_handler(110),
    get_handler(111),
    get_handler(112),
    get_handler(113),
    get_handler(114),
    get_handler(115),
    get_handler(116),
    get_handler(117),
    get_handler(118),
    get_handler(119),
    get_handler(120),
    get_handler(121),
    get_handler(122),
    get_handler(123),
    get_handler(124),
    get_handler(125),
    get_handler(126),
    get_handler(127),
    get_handler(128),
    get_handler(129),
    get_handler(130),
    get_handler(131),
    get_handler(132),
    get_handler(133),
    get_handler(134),
    get_handler(135),
    get_handler(136),
    get_handler(137),
    get_handler(138),
    get_handler(139),
    get_handler(140),
    get_handler(141),
    get_handler(142),
    get_handler(143),
    get_handler(144),
    get_handler(145),
    get_handler(146),
    get_handler(147),
    get_handler(148),
    get_handler(149),
    get_handler(150),
    get_handler(151),
    get_handler(152),
    get_handler(153),
    get_handler(154),
    get_handler(155),
    get_handler(156),
    get_handler(157),
    get_handler(158),
    get_handler(159),
    get_handler(160),
    get_handler(161),
    get_handler(162),
    get_handler(163),
    get_handler(164),
    get_handler(165),
    get_handler(166),
    get_handler(167),
    get_handler(168),
    get_handler(169),
    get_handler(170),
    get_handler(171),
    get_handler(172),
    get_handler(173),
    get_handler(174),
    get_handler(175),
    get_handler(176),
    get_handler(177),
    get_handler(178),
    get_handler(179),
    get_handler(180),
    get_handler(181),
    get_handler(182),
    get_handler(183),
    get_handler(184),
    get_handler(185),
    get_handler(186),
    get_handler(187),
    get_handler(188),
    get_handler(189),
    get_handler(190),
    get_handler(191),
    get_handler(192),
    get_handler(193),
    get_handler(194),
    get_handler(195),
    get_handler(196),
    get_handler(197),
    get_handler(198),
    get_handler(199),
    get_handler(200),

    get_handler(201),
    get_handler(202),
    get_handler(203),
    get_handler(204),
    get_handler(205),
    get_handler(206),
    get_handler(207),
    get_handler(208),
    get_handler(209),
    get_handler(210),
    get_handler(211),
    get_handler(212),
    get_handler(213),
    get_handler(214),
    get_handler(215),
    get_handler(216),
    get_handler(217),
    get_handler(218),
    get_handler(219),
    get_handler(220),
    get_handler(221),
    get_handler(222),
    get_handler(223),
    get_handler(224),
    get_handler(225),
    get_handler(226),
    get_handler(227),
    get_handler(228),
    get_handler(229),
    get_handler(230),
    get_handler(231),
    get_handler(232),
    get_handler(233),
    get_handler(234),
    get_handler(235),
    get_handler(236),
    get_handler(237),
    get_handler(238),
    get_handler(239),
    get_handler(240),
    get_handler(241),
    get_handler(242),
    get_handler(243),
    get_handler(244),
    get_handler(245),
    get_handler(246),
    get_handler(247),
    get_handler(248),
    get_handler(249),
    get_handler(250),
    get_handler(251),
    get_handler(252),
    get_handler(253),
    get_handler(254),
    get_handler(255),
};

pub fn setup() void {
    for (idt) |*entry, i| {
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

    pub fn format(frame: *const Frame, comptime _: []const u8, _: common.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try writer.writeAll("\n");
        inline for (common.fields(Frame)) |field| {
            const name = field.name;
            const value = @field(frame, field.name);
            const args = .{ name, value };

            switch (field.type) {
                u64 => try common.internal_format(writer, "\t{s}: 0x{x}\n", args),
                RFLAGS => try common.internal_format(writer, "\t{s}: {}\n", args),
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

pub fn get_handler(comptime interrupt_number: u64) HandlerPrototype {
    const has_error_code = switch (interrupt_number) {
        8, 10, 11, 12, 13, 14, 17 => true,
        else => false,
    };
    const is_exception = switch (interrupt_number) {
        0...31 => true,
        else => false,
    };

    return struct {
        pub fn handler() align(0x10) callconv(.Naked) void {
            if (comptime !has_error_code) asm volatile ("push $0");
            asm volatile ("push %[interrupt_number]"
                :
                : [interrupt_number] "i" (interrupt_number),
            );

            const comptimePrint = common.std.fmt.comptimePrint;

            if (is_exception) {
                const Tag = enum(u8) {
                    kernel_fault,
                    save_trap,
                    disabled_test,
                    save_enabled,
                    do_save,
                };

                asm volatile (
                // if CS.CPL == 0
                    \\testb $3, 24(%rsp)
                );
                asm volatile (comptimePrint("jz {}f", .{@enumToInt(Tag.kernel_fault)}));
                asm volatile (
                // User code
                    \\pushq %rcx
                    \\movq current_core_director_data(%rip), %rcx
                );
                asm volatile (comptimePrint("movq {}(%rcx), %rcx", .{@offsetOf(CoreDirectorData, "dispatcher_handle")}));
                asm volatile (
                // Is page fault?
                    \\cmpq %[page_fault], 8(%rsp)
                    :
                    : [page_fault] "i" (Exception.page_fault),
                );
                asm volatile (comptimePrint("jne {}", .{@enumToInt(Tag.save_trap)}));
                asm volatile (comptimePrint("cmpl $0, {}(%rcx)", .{@offsetOf(CoreDirectorData, "disabled")}));
                asm volatile (comptimePrint("jne {}", .{@enumToInt(Tag.save_trap)}));
                asm volatile (
                    \\pushq %rbx
                    \\movq 4 * 8(%rsp), %rbx
                );

                asm volatile (comptimePrint("cmpq {}(%rcx), %rbx", .{@offsetOf(privileged.arch.CoreDirectorShared, "crit_pc_low")}));
                asm volatile (comptimePrint("jae {}f", .{@enumToInt(Tag.disabled_test)}));
                asm volatile (comptimePrint("{}:", .{@enumToInt(Tag.save_enabled)}));
                asm volatile (
                    \\popq %rbx
                );
                asm volatile (comptimePrint("addq ${}, %rcx", .{@offsetOf(privileged.arch.CoreDirectorShared, "enabled_save_area")}));
                asm volatile (comptimePrint("jmp {}f", .{@enumToInt(Tag.do_save)}));
                asm volatile (comptimePrint("{}:", .{@enumToInt(Tag.disabled_test)}));
                asm volatile (comptimePrint("cmpq {}(%rcx), %rbx", .{@offsetOf(privileged.arch.CoreDirectorShared, "crit_pc_high")}));
                asm volatile (comptimePrint("jae {}b", .{@enumToInt(Tag.save_enabled)}));
                asm volatile (
                    \\popq %rbx
                );
                asm volatile (comptimePrint("{}:", .{@enumToInt(Tag.save_trap)}));
                asm volatile (
                    \\addq %[trap_save_area_offset], %rcx
                    :
                    : [trap_save_area_offset] "i" (@offsetOf(privileged.arch.CoreDirectorShared, "trap_save_area")),
                );
                asm volatile (comptimePrint("{}:", .{@enumToInt(Tag.do_save)}));
                asm volatile (
                    \\movq %rax, 0*8(%rcx)
                    \\popq %rax
                    \\movq %rbx,  1*8(%rcx)
                    \\movq %rax,  2*8(%rcx)
                    \\movq %rdx,  3*8(%rcx)
                    \\movq %rsi,  4*8(%rcx)
                    \\movq %rdi,  5*8(%rcx)
                    \\movq %rbp,  6*8(%rcx)
                    \\movq %r8,   8*8(%rcx)
                    \\movq %r9,   9*8(%rcx)
                    \\movq %r10, 10*8(%rcx)
                    \\movq %r11, 11*8(%rcx)
                    \\movq %r12, 12*8(%rcx)
                    \\movq %r13, 13*8(%rcx)
                    \\movq %r14, 14*8(%rcx)
                    \\movq %r15, 15*8(%rcx)
                );

                asm volatile (comptimePrint("mov %fs, {}(%rcx)", .{@offsetOf(x86_64.Registers, "fs")}));
                asm volatile (comptimePrint("mov %gs, {}(%rcx)", .{@offsetOf(x86_64.Registers, "gs")}));
                asm volatile (comptimePrint("fxsave {}(%rcx)", .{@offsetOf(x86_64.Registers, "fxsave_area")}));
                asm volatile (
                // vector number
                    \\popq %rdi 
                    // error code
                    \\popq %rsi
                    // CPU save area
                    \\movq %rsp, %rdx
                    \\call user_exception_handler
                    \\iretq
                );

                asm volatile (comptimePrint("{}:", .{@enumToInt(Tag.kernel_fault)}));
                asm volatile (
                // SS
                    \\pushq 6 * 8(%rsp)
                    // CS
                    \\pushq 4 * 8(%rsp)
                    // RFLAGS
                    \\pushq 7 * 8(%rsp)
                    // RIP
                    \\pushq 5 * 8(%rsp)
                    \\pushq %r15
                    \\pushq %r14
                    \\pushq %r13
                    \\pushq %r12
                    \\pushq %r11
                    \\pushq %r10
                    \\pushq %r9
                    \\pushq %r8
                    // RSP
                    \\pushq 17 * 8 (%rsp)
                    \\pushq %rbp
                    \\pushq %rdi
                    \\pushq %rsi
                    \\pushq %rdx
                    \\pushq %rcx
                    \\pushq %rbx
                    \\pushq %rax
                    \\movq 20*8(%rsp), %rdi
                    \\movq 21*8(%rsp), %rsi
                    \\movq %rsp, %rdx
                    \\jmp kernel_exception_handler
                );
            } else {
                const Tag = enum(u8) {
                    call_handle_irq,
                    irq_save_disabled,
                    irq_disabled_test,
                    irq_save_enabled,
                    irq_do_save,
                };
                asm volatile (
                // if CS.CPL == 0
                    \\testb $3, 16(%rsp)
                );
                asm volatile (comptimePrint("jz {}", .{@enumToInt(Tag.call_handle_irq)}));

                asm volatile (
                    \\pushq %rdx
                    \\movq current_core_director_data(%rip), %rdx
                );

                asm volatile (comptimePrint("movq {}(%rdx), %rdx", .{@offsetOf(CoreDirectorData, "dispatcher_handle")}));
                asm volatile (comptimePrint("cmpl $0, {}(%rdx)", .{@offsetOf(CoreDirectorData, "disabled")}));
                asm volatile (comptimePrint("jne {}", .{@enumToInt(Tag.irq_save_disabled)}));
                asm volatile (
                    \\pushq %rbx
                    \\movq 24(%rsp), %rbx
                );

                asm volatile (comptimePrint("cmpq {}(%rdx), %rbx", .{@offsetOf(privileged.arch.CoreDirectorShared, "crit_pc_low")}));
                asm volatile (comptimePrint("jae {}", .{@enumToInt(Tag.irq_disabled_test)}));
                asm volatile (comptimePrint("{}:", .{@enumToInt(Tag.irq_save_enabled)}));
                asm volatile (
                    \\popq %rbx
                    \\addq %[enabled_area_offset], %rbx
                    :
                    : [enabled_area_offset] "i" (@offsetOf(privileged.arch.CoreDirectorShared, "enabled_save_area")),
                );
                asm volatile (comptimePrint("jmp {}", .{@enumToInt(Tag.irq_do_save)}));
                asm volatile (comptimePrint("{}:", .{@enumToInt(Tag.irq_disabled_test)}));
                asm volatile (comptimePrint("cmpq {}(%rdx), %rbx", .{@offsetOf(privileged.arch.CoreDirectorShared, "crit_pc_high")}));
                asm volatile (comptimePrint("jae {}", .{@enumToInt(Tag.irq_save_enabled)}));
                asm volatile (
                    \\popq %rbx
                );
                asm volatile (comptimePrint("{}:", .{@enumToInt(Tag.irq_save_disabled)}));
                asm volatile (
                    \\addq %[disabled_area_offset], %rdx
                    :
                    : [disabled_area_offset] "i" (@offsetOf(privileged.arch.CoreDirectorShared, "disabled_save_area")),
                );
                asm volatile (comptimePrint("{}:", .{@enumToInt(Tag.irq_do_save)}));
                asm volatile (
                    \\movq %rax,  0*8(%rdx)
                    \\movq %rbx,  1*8(%rdx)
                    \\movq %rcx,  2*8(%rdx)
                    \\popq %rax
                    \\movq %rax,  3*8(%rdx)
                    \\movq %rsi,  4*8(%rdx)
                    \\movq %rdi,  5*8(%rdx)
                    \\movq %rbp,  6*8(%rdx)
                    \\movq %r8,   8*8(%rdx)
                    \\movq %r9,   9*8(%rdx)
                    \\movq %r10, 10*8(%rdx)
                    \\movq %r11, 11*8(%rdx)
                    \\movq %r12, 12*8(%rdx)
                    \\movq %r13, 13*8(%rdx)
                    \\movq %r14, 14*8(%rdx)
                    \\movq %r15, 15*8(%rdx)
                );

                asm volatile (comptimePrint("mov %fs, {}(%rdx)", .{@offsetOf(x86_64.Registers, "fs")}));
                asm volatile (comptimePrint("mov %gs, {}(%rdx)", .{@offsetOf(x86_64.Registers, "gs")}));
                asm volatile (comptimePrint("fxsave {}(%rdx)", .{@offsetOf(x86_64.Registers, "fxsave_area")}));

                asm volatile (
                    \\popq %rdi
                    \\movq %rsp, %rsi
                    \\jmp irq_handler
                );
                asm volatile (comptimePrint("{}:", .{@enumToInt(Tag.call_handle_irq)}));
                asm volatile (
                    \\popq %rdi
                    \\callq handle_irq
                );
            }

            @panic("Interrupt epilogue didn't iret properly");
        }
    }.handler;
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
