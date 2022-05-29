const kernel = @import("../../kernel.zig");
const PIC = @import("pic.zig");

const log = kernel.log.scoped(.interrupts);
const IDTEntry = u128;
export var idt: [256]Descriptor align(0x1000) = undefined;

const Descriptor = packed struct {
    offset_low: u16,
    segment_selector: u16,
    interrupt_stack_table: u3,
    reserved: u5 = 0,
    type: u4,
    reserved1: u1 = 0,
    descriptor_privilege_level: u2,
    present: u1,
    offset_mid: u16,
    offset_high: u32,
    reserved2: u32 = 0,
};

const InterruptHandler = fn () callconv(.Naked) void;

pub fn install_interrupt_handlers() void {
    install_interrupt_handler(0, comptime make_interrupt_handler(0, false));
    install_interrupt_handler(1, comptime make_interrupt_handler(1, false));
    install_interrupt_handler(2, comptime make_interrupt_handler(2, false));
    install_interrupt_handler(3, comptime make_interrupt_handler(3, false));
    install_interrupt_handler(4, comptime make_interrupt_handler(4, false));
    install_interrupt_handler(5, comptime make_interrupt_handler(5, false));
    install_interrupt_handler(6, comptime make_interrupt_handler(6, false));
    install_interrupt_handler(7, comptime make_interrupt_handler(7, false));
    install_interrupt_handler(8, comptime make_interrupt_handler(8, true));
    install_interrupt_handler(9, comptime make_interrupt_handler(9, false));
    install_interrupt_handler(10, comptime make_interrupt_handler(10, true));
    install_interrupt_handler(11, comptime make_interrupt_handler(11, true));
    install_interrupt_handler(12, comptime make_interrupt_handler(12, true));
    install_interrupt_handler(13, comptime make_interrupt_handler(13, true));
    install_interrupt_handler(14, comptime make_interrupt_handler(14, true));
    install_interrupt_handler(15, comptime make_interrupt_handler(15, false));
    install_interrupt_handler(16, comptime make_interrupt_handler(16, false));
    install_interrupt_handler(17, comptime make_interrupt_handler(17, true));
    install_interrupt_handler(18, comptime make_interrupt_handler(18, false));
    install_interrupt_handler(19, comptime make_interrupt_handler(19, false));
    install_interrupt_handler(20, comptime make_interrupt_handler(20, false));
    install_interrupt_handler(21, comptime make_interrupt_handler(21, false));
    install_interrupt_handler(22, comptime make_interrupt_handler(22, false));
    install_interrupt_handler(23, comptime make_interrupt_handler(23, false));
    install_interrupt_handler(24, comptime make_interrupt_handler(24, false));
    install_interrupt_handler(25, comptime make_interrupt_handler(25, false));
    install_interrupt_handler(26, comptime make_interrupt_handler(26, false));
    install_interrupt_handler(27, comptime make_interrupt_handler(27, false));
    install_interrupt_handler(28, comptime make_interrupt_handler(28, false));
    install_interrupt_handler(29, comptime make_interrupt_handler(29, false));
    install_interrupt_handler(30, comptime make_interrupt_handler(30, false));
    install_interrupt_handler(31, comptime make_interrupt_handler(31, false));
    install_interrupt_handler(32, comptime make_interrupt_handler(32, false));
    install_interrupt_handler(33, comptime make_interrupt_handler(33, false));
    install_interrupt_handler(34, comptime make_interrupt_handler(34, false));
    install_interrupt_handler(35, comptime make_interrupt_handler(35, false));
    install_interrupt_handler(36, comptime make_interrupt_handler(36, false));
    install_interrupt_handler(37, comptime make_interrupt_handler(37, false));
    install_interrupt_handler(38, comptime make_interrupt_handler(38, false));
    install_interrupt_handler(39, comptime make_interrupt_handler(39, false));
    install_interrupt_handler(40, comptime make_interrupt_handler(40, false));
    install_interrupt_handler(41, comptime make_interrupt_handler(41, false));
    install_interrupt_handler(42, comptime make_interrupt_handler(42, false));
    install_interrupt_handler(43, comptime make_interrupt_handler(43, false));
    install_interrupt_handler(44, comptime make_interrupt_handler(44, false));
    install_interrupt_handler(45, comptime make_interrupt_handler(45, false));
    install_interrupt_handler(46, comptime make_interrupt_handler(46, false));
    install_interrupt_handler(47, comptime make_interrupt_handler(47, false));
    install_interrupt_handler(48, comptime make_interrupt_handler(48, false));
    install_interrupt_handler(49, comptime make_interrupt_handler(49, false));
    install_interrupt_handler(50, comptime make_interrupt_handler(50, false));
    install_interrupt_handler(51, comptime make_interrupt_handler(51, false));
    install_interrupt_handler(52, comptime make_interrupt_handler(52, false));
    install_interrupt_handler(53, comptime make_interrupt_handler(53, false));
    install_interrupt_handler(54, comptime make_interrupt_handler(54, false));
    install_interrupt_handler(55, comptime make_interrupt_handler(55, false));
    install_interrupt_handler(56, comptime make_interrupt_handler(56, false));
    install_interrupt_handler(57, comptime make_interrupt_handler(57, false));
    install_interrupt_handler(58, comptime make_interrupt_handler(58, false));
    install_interrupt_handler(59, comptime make_interrupt_handler(59, false));
    install_interrupt_handler(60, comptime make_interrupt_handler(60, false));
    install_interrupt_handler(61, comptime make_interrupt_handler(61, false));
    install_interrupt_handler(62, comptime make_interrupt_handler(62, false));
    install_interrupt_handler(63, comptime make_interrupt_handler(63, false));
    install_interrupt_handler(64, comptime make_interrupt_handler(64, false));
    install_interrupt_handler(65, comptime make_interrupt_handler(65, false));
    install_interrupt_handler(66, comptime make_interrupt_handler(66, false));
    install_interrupt_handler(67, comptime make_interrupt_handler(67, false));
    install_interrupt_handler(68, comptime make_interrupt_handler(68, false));
    install_interrupt_handler(69, comptime make_interrupt_handler(69, false));
    install_interrupt_handler(70, comptime make_interrupt_handler(70, false));
    install_interrupt_handler(71, comptime make_interrupt_handler(71, false));
    install_interrupt_handler(72, comptime make_interrupt_handler(72, false));
    install_interrupt_handler(73, comptime make_interrupt_handler(73, false));
    install_interrupt_handler(74, comptime make_interrupt_handler(74, false));
    install_interrupt_handler(75, comptime make_interrupt_handler(75, false));
    install_interrupt_handler(76, comptime make_interrupt_handler(76, false));
    install_interrupt_handler(77, comptime make_interrupt_handler(77, false));
    install_interrupt_handler(78, comptime make_interrupt_handler(78, false));
    install_interrupt_handler(79, comptime make_interrupt_handler(79, false));
    install_interrupt_handler(80, comptime make_interrupt_handler(80, false));
    install_interrupt_handler(81, comptime make_interrupt_handler(81, false));
    install_interrupt_handler(82, comptime make_interrupt_handler(82, false));
    install_interrupt_handler(83, comptime make_interrupt_handler(83, false));
    install_interrupt_handler(84, comptime make_interrupt_handler(84, false));
    install_interrupt_handler(85, comptime make_interrupt_handler(85, false));
    install_interrupt_handler(86, comptime make_interrupt_handler(86, false));
    install_interrupt_handler(87, comptime make_interrupt_handler(87, false));
    install_interrupt_handler(88, comptime make_interrupt_handler(88, false));
    install_interrupt_handler(89, comptime make_interrupt_handler(89, false));
    install_interrupt_handler(90, comptime make_interrupt_handler(90, false));
    install_interrupt_handler(91, comptime make_interrupt_handler(91, false));
    install_interrupt_handler(92, comptime make_interrupt_handler(92, false));
    install_interrupt_handler(93, comptime make_interrupt_handler(93, false));
    install_interrupt_handler(94, comptime make_interrupt_handler(94, false));
    install_interrupt_handler(95, comptime make_interrupt_handler(95, false));
    install_interrupt_handler(96, comptime make_interrupt_handler(96, false));
    install_interrupt_handler(97, comptime make_interrupt_handler(97, false));
    install_interrupt_handler(98, comptime make_interrupt_handler(98, false));
    install_interrupt_handler(99, comptime make_interrupt_handler(99, false));

    install_interrupt_handler(100, comptime make_interrupt_handler(100, false));
    install_interrupt_handler(101, comptime make_interrupt_handler(101, false));
    install_interrupt_handler(102, comptime make_interrupt_handler(102, false));
    install_interrupt_handler(103, comptime make_interrupt_handler(103, false));
    install_interrupt_handler(104, comptime make_interrupt_handler(104, false));
    install_interrupt_handler(105, comptime make_interrupt_handler(105, false));
    install_interrupt_handler(106, comptime make_interrupt_handler(106, false));
    install_interrupt_handler(107, comptime make_interrupt_handler(107, false));
    install_interrupt_handler(108, comptime make_interrupt_handler(108, false));
    install_interrupt_handler(109, comptime make_interrupt_handler(109, false));
    install_interrupt_handler(110, comptime make_interrupt_handler(110, false));
    install_interrupt_handler(111, comptime make_interrupt_handler(111, false));
    install_interrupt_handler(112, comptime make_interrupt_handler(112, false));
    install_interrupt_handler(113, comptime make_interrupt_handler(113, false));
    install_interrupt_handler(114, comptime make_interrupt_handler(114, false));
    install_interrupt_handler(115, comptime make_interrupt_handler(115, false));
    install_interrupt_handler(116, comptime make_interrupt_handler(116, false));
    install_interrupt_handler(117, comptime make_interrupt_handler(117, false));
    install_interrupt_handler(118, comptime make_interrupt_handler(118, false));
    install_interrupt_handler(119, comptime make_interrupt_handler(119, false));
    install_interrupt_handler(120, comptime make_interrupt_handler(120, false));
    install_interrupt_handler(121, comptime make_interrupt_handler(121, false));
    install_interrupt_handler(122, comptime make_interrupt_handler(122, false));
    install_interrupt_handler(123, comptime make_interrupt_handler(123, false));
    install_interrupt_handler(124, comptime make_interrupt_handler(124, false));
    install_interrupt_handler(125, comptime make_interrupt_handler(125, false));
    install_interrupt_handler(126, comptime make_interrupt_handler(126, false));
    install_interrupt_handler(127, comptime make_interrupt_handler(127, false));
    install_interrupt_handler(128, comptime make_interrupt_handler(128, false));
    install_interrupt_handler(129, comptime make_interrupt_handler(129, false));
    install_interrupt_handler(130, comptime make_interrupt_handler(130, false));
    install_interrupt_handler(131, comptime make_interrupt_handler(131, false));
    install_interrupt_handler(132, comptime make_interrupt_handler(132, false));
    install_interrupt_handler(133, comptime make_interrupt_handler(133, false));
    install_interrupt_handler(134, comptime make_interrupt_handler(134, false));
    install_interrupt_handler(135, comptime make_interrupt_handler(135, false));
    install_interrupt_handler(136, comptime make_interrupt_handler(136, false));
    install_interrupt_handler(137, comptime make_interrupt_handler(137, false));
    install_interrupt_handler(138, comptime make_interrupt_handler(138, false));
    install_interrupt_handler(139, comptime make_interrupt_handler(139, false));
    install_interrupt_handler(140, comptime make_interrupt_handler(140, false));
    install_interrupt_handler(141, comptime make_interrupt_handler(141, false));
    install_interrupt_handler(142, comptime make_interrupt_handler(142, false));
    install_interrupt_handler(143, comptime make_interrupt_handler(143, false));
    install_interrupt_handler(144, comptime make_interrupt_handler(144, false));
    install_interrupt_handler(145, comptime make_interrupt_handler(145, false));
    install_interrupt_handler(146, comptime make_interrupt_handler(146, false));
    install_interrupt_handler(147, comptime make_interrupt_handler(147, false));
    install_interrupt_handler(148, comptime make_interrupt_handler(148, false));
    install_interrupt_handler(149, comptime make_interrupt_handler(149, false));
    install_interrupt_handler(150, comptime make_interrupt_handler(150, false));
    install_interrupt_handler(151, comptime make_interrupt_handler(151, false));
    install_interrupt_handler(152, comptime make_interrupt_handler(152, false));
    install_interrupt_handler(153, comptime make_interrupt_handler(153, false));
    install_interrupt_handler(154, comptime make_interrupt_handler(154, false));
    install_interrupt_handler(155, comptime make_interrupt_handler(155, false));
    install_interrupt_handler(156, comptime make_interrupt_handler(156, false));
    install_interrupt_handler(157, comptime make_interrupt_handler(157, false));
    install_interrupt_handler(158, comptime make_interrupt_handler(158, false));
    install_interrupt_handler(159, comptime make_interrupt_handler(159, false));
    install_interrupt_handler(160, comptime make_interrupt_handler(160, false));
    install_interrupt_handler(161, comptime make_interrupt_handler(161, false));
    install_interrupt_handler(162, comptime make_interrupt_handler(162, false));
    install_interrupt_handler(163, comptime make_interrupt_handler(163, false));
    install_interrupt_handler(164, comptime make_interrupt_handler(164, false));
    install_interrupt_handler(165, comptime make_interrupt_handler(165, false));
    install_interrupt_handler(166, comptime make_interrupt_handler(166, false));
    install_interrupt_handler(167, comptime make_interrupt_handler(167, false));
    install_interrupt_handler(168, comptime make_interrupt_handler(168, false));
    install_interrupt_handler(169, comptime make_interrupt_handler(169, false));
    install_interrupt_handler(170, comptime make_interrupt_handler(170, false));
    install_interrupt_handler(171, comptime make_interrupt_handler(171, false));
    install_interrupt_handler(172, comptime make_interrupt_handler(172, false));
    install_interrupt_handler(173, comptime make_interrupt_handler(173, false));
    install_interrupt_handler(174, comptime make_interrupt_handler(174, false));
    install_interrupt_handler(175, comptime make_interrupt_handler(175, false));
    install_interrupt_handler(176, comptime make_interrupt_handler(176, false));
    install_interrupt_handler(177, comptime make_interrupt_handler(177, false));
    install_interrupt_handler(178, comptime make_interrupt_handler(178, false));
    install_interrupt_handler(179, comptime make_interrupt_handler(179, false));
    install_interrupt_handler(180, comptime make_interrupt_handler(180, false));
    install_interrupt_handler(181, comptime make_interrupt_handler(181, false));
    install_interrupt_handler(182, comptime make_interrupt_handler(182, false));
    install_interrupt_handler(183, comptime make_interrupt_handler(183, false));
    install_interrupt_handler(184, comptime make_interrupt_handler(184, false));
    install_interrupt_handler(185, comptime make_interrupt_handler(185, false));
    install_interrupt_handler(186, comptime make_interrupt_handler(186, false));
    install_interrupt_handler(187, comptime make_interrupt_handler(187, false));
    install_interrupt_handler(188, comptime make_interrupt_handler(188, false));
    install_interrupt_handler(189, comptime make_interrupt_handler(189, false));
    install_interrupt_handler(190, comptime make_interrupt_handler(190, false));
    install_interrupt_handler(191, comptime make_interrupt_handler(191, false));
    install_interrupt_handler(192, comptime make_interrupt_handler(192, false));
    install_interrupt_handler(193, comptime make_interrupt_handler(193, false));
    install_interrupt_handler(194, comptime make_interrupt_handler(194, false));
    install_interrupt_handler(195, comptime make_interrupt_handler(195, false));
    install_interrupt_handler(196, comptime make_interrupt_handler(196, false));
    install_interrupt_handler(197, comptime make_interrupt_handler(197, false));
    install_interrupt_handler(198, comptime make_interrupt_handler(198, false));
    install_interrupt_handler(199, comptime make_interrupt_handler(199, false));
    install_interrupt_handler(200, comptime make_interrupt_handler(200, false));

    install_interrupt_handler(200, comptime make_interrupt_handler(200, false));
    install_interrupt_handler(201, comptime make_interrupt_handler(201, false));
    install_interrupt_handler(202, comptime make_interrupt_handler(202, false));
    install_interrupt_handler(203, comptime make_interrupt_handler(203, false));
    install_interrupt_handler(204, comptime make_interrupt_handler(204, false));
    install_interrupt_handler(205, comptime make_interrupt_handler(205, false));
    install_interrupt_handler(206, comptime make_interrupt_handler(206, false));
    install_interrupt_handler(207, comptime make_interrupt_handler(207, false));
    install_interrupt_handler(208, comptime make_interrupt_handler(208, false));
    install_interrupt_handler(209, comptime make_interrupt_handler(209, false));
    install_interrupt_handler(210, comptime make_interrupt_handler(210, false));
    install_interrupt_handler(211, comptime make_interrupt_handler(211, false));
    install_interrupt_handler(212, comptime make_interrupt_handler(212, false));
    install_interrupt_handler(213, comptime make_interrupt_handler(213, false));
    install_interrupt_handler(214, comptime make_interrupt_handler(214, false));
    install_interrupt_handler(215, comptime make_interrupt_handler(215, false));
    install_interrupt_handler(216, comptime make_interrupt_handler(216, false));
    install_interrupt_handler(217, comptime make_interrupt_handler(217, false));
    install_interrupt_handler(218, comptime make_interrupt_handler(218, false));
    install_interrupt_handler(219, comptime make_interrupt_handler(219, false));
    install_interrupt_handler(220, comptime make_interrupt_handler(220, false));
    install_interrupt_handler(221, comptime make_interrupt_handler(221, false));
    install_interrupt_handler(222, comptime make_interrupt_handler(222, false));
    install_interrupt_handler(223, comptime make_interrupt_handler(223, false));
    install_interrupt_handler(224, comptime make_interrupt_handler(224, false));
    install_interrupt_handler(225, comptime make_interrupt_handler(225, false));
    install_interrupt_handler(226, comptime make_interrupt_handler(226, false));
    install_interrupt_handler(227, comptime make_interrupt_handler(227, false));
    install_interrupt_handler(228, comptime make_interrupt_handler(228, false));
    install_interrupt_handler(229, comptime make_interrupt_handler(229, false));
    install_interrupt_handler(230, comptime make_interrupt_handler(230, false));
    install_interrupt_handler(231, comptime make_interrupt_handler(231, false));
    install_interrupt_handler(232, comptime make_interrupt_handler(232, false));
    install_interrupt_handler(233, comptime make_interrupt_handler(233, false));
    install_interrupt_handler(234, comptime make_interrupt_handler(234, false));
    install_interrupt_handler(235, comptime make_interrupt_handler(235, false));
    install_interrupt_handler(236, comptime make_interrupt_handler(236, false));
    install_interrupt_handler(237, comptime make_interrupt_handler(237, false));
    install_interrupt_handler(238, comptime make_interrupt_handler(238, false));
    install_interrupt_handler(239, comptime make_interrupt_handler(239, false));
    install_interrupt_handler(240, comptime make_interrupt_handler(240, false));
    install_interrupt_handler(241, comptime make_interrupt_handler(241, false));
    install_interrupt_handler(242, comptime make_interrupt_handler(242, false));
    install_interrupt_handler(243, comptime make_interrupt_handler(243, false));
    install_interrupt_handler(244, comptime make_interrupt_handler(244, false));
    install_interrupt_handler(245, comptime make_interrupt_handler(245, false));
    install_interrupt_handler(246, comptime make_interrupt_handler(246, false));
    install_interrupt_handler(247, comptime make_interrupt_handler(247, false));
    install_interrupt_handler(248, comptime make_interrupt_handler(248, false));
    install_interrupt_handler(249, comptime make_interrupt_handler(249, false));
    install_interrupt_handler(250, comptime make_interrupt_handler(250, false));
    install_interrupt_handler(251, comptime make_interrupt_handler(251, false));
    install_interrupt_handler(252, comptime make_interrupt_handler(252, false));
    install_interrupt_handler(253, comptime make_interrupt_handler(253, false));
    install_interrupt_handler(254, comptime make_interrupt_handler(254, false));
    install_interrupt_handler(255, comptime make_interrupt_handler(255, false));
}

pub const Register = packed struct {
    limit: u16 = @sizeOf(@TypeOf(idt)) - 1,
    address: u64,
};

pub inline fn load_idt() void {
    const idtr = Register{
        .address = @ptrToInt(&idt),
    };

    asm volatile (
        \\lidt (%[idt_address])
        :
        : [idt_address] "r" (&idtr),
    );
}
pub inline fn enable() void {
    asm volatile ("sti");
}

pub inline fn disable() void {
    asm volatile ("cli");
}
pub fn init() void {
    // Initialize interrupts
    log.debug("Initializing interrupts", .{});
    PIC.disable();
    log.debug("Reached to the goal", .{});
    install_interrupt_handlers();
    log.debug("Installed interrupt handlers", .{});
    load_idt();
    log.debug("Loaded IDT", .{});
}

fn install_interrupt_handler(comptime number: u64, comptime handler: InterruptHandler) void {
    const handler_address = @ptrToInt(handler);
    idt[number] = Descriptor{
        .offset_low = @truncate(u16, handler_address),
        .offset_mid = @truncate(u16, handler_address >> 16),
        .offset_high = @truncate(u32, handler_address >> 32),
        .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
        .interrupt_stack_table = 0,
        .type = 0xe,
        .descriptor_privilege_level = 0,
        .present = 1,
    };
}

export fn interrupt_handler() callconv(.C) void {
    while (true) {}
}

pub fn make_interrupt_handler(comptime number: u64, comptime has_error_code: bool) InterruptHandler {
    return struct {
        pub fn handler() callconv(.Naked) void {
            if (comptime !has_error_code) asm volatile ("push $0");
            asm volatile ("push %[interrupt_number]"
                :
                : [interrupt_number] "i" (number),
            );

            asm volatile (
                \\cld
                \\push %%rax
                \\push %%rbx
                \\push %%rcx
                \\push %%rdx
                \\push %%rbp
                \\push %%rsi
                \\push %%rdi
                \\push %%r8
                \\push %%r9
                \\push %%r10
                \\push %%r11
                \\push %%r12
                \\push %%r13
                \\push %%r14
                \\push %%r15
                \\mov $0x123456789ABCDEF, %%rax
                \\push %%rax
                \\mov %%rsp, %%rbx
                \\and $~0xf, %%rsp 
                \\fxsave -0x200(%%rsp)
                \\mov %%rbx, %%rsp
                \\sub $0x210, %%rsp
                \\xor %%rax, %%rax
                \\mov %%ds, %%ax
                \\push %%rax
                \\xor %%rax, %%rax
                \\mov %%es, %%rax
                \\push %%rax
                \\mov %%rsp, %%rdi
                \\mov $0x10, %%ax
                \\mov %%ax, %%ds
                \\mov %%ax, %%es
                \\mov %%rsp, %%rbx
                \\and $~0xf, %%rsp 
            );

            asm volatile (
                \\ call interrupt_handler
            );

            asm volatile (
                \\mov %%rbx, %%rsp
                \\pop %%rbx
                \\mov %%bx, %%es
                \\pop %%rbx
                \\mov %%bx, %%ds
                \\add $0x210, %%rsp
                \\mov %%rsp, %%rbx
                \\and $~0xf, %%rbx
                \\and $~0xf, %%rbx
                \\fxrstor -0x200(%%rbx)
                // @TODO: if this is a new thread, we must initialize the FPU
                \\pop %%rax
                \\pop %%r15
                \\pop %%r14
                \\pop %%r13
                \\pop %%r12
                \\pop %%r11
                \\pop %%r10
                \\pop %%r9
                \\pop %%r8
                \\pop %%rbp
                \\pop %%rdi
                \\pop %%rsi
                \\pop %%rdx
                \\pop %%rcx
                \\pop %%rbx
                \\pop %%rax
                \\add $0x10, %%rsp
                \\iretq
            );

            unreachable;
        }
    }.handler;
}

//pub const Context = extern struct {
//es: u64,
//ds: u64,
//fx_save: [512 + 16]u8,
//_check: u64,
//r15: u64,
//r14: u64,
//r13: u64,
//r12: u64,
//r11: u64,
//r10: u64,
//r9: u64,
//r8: u64,
//rbp: u64,
//rdi: u64,
//rsi: u64,
//rdx: u64,
//rcx: u64,
//rbx: u64,
//rax: u64,
//interrupt_number: u64,
//error_code: u64,
//rip: u64,
//cs: u64,
//eflags: u64,
//rsp: u64,
//ss: u64,
//};
