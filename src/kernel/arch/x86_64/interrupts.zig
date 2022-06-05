const kernel = @import("../../kernel.zig");
const PIC = @import("pic.zig");
const IDT = @import("idt.zig");
const GDT = @import("gdt.zig");
const x86_64 = @import("../x86_64.zig");

const interrupts = @This();

const log = kernel.log.scoped(.interrupts);
const Handler = fn () callconv(.Naked) void;

export var idt: IDT = undefined;

pub fn install_interrupt_handlers() void {
    idt.add_interrupt_handler(get_handler_descriptor(0, false));
    idt.add_interrupt_handler(get_handler_descriptor(1, false));
    idt.add_interrupt_handler(get_handler_descriptor(2, false));
    idt.add_interrupt_handler(get_handler_descriptor(3, false));
    idt.add_interrupt_handler(get_handler_descriptor(4, false));
    idt.add_interrupt_handler(get_handler_descriptor(5, false));
    idt.add_interrupt_handler(get_handler_descriptor(6, false));
    idt.add_interrupt_handler(get_handler_descriptor(7, false));
    idt.add_interrupt_handler(get_handler_descriptor(8, true));
    idt.add_interrupt_handler(get_handler_descriptor(9, false));
    idt.add_interrupt_handler(get_handler_descriptor(10, true));
    idt.add_interrupt_handler(get_handler_descriptor(11, true));
    idt.add_interrupt_handler(get_handler_descriptor(12, true));
    idt.add_interrupt_handler(get_handler_descriptor(13, true));
    idt.add_interrupt_handler(get_handler_descriptor(14, true));
    idt.add_interrupt_handler(get_handler_descriptor(15, false));
    idt.add_interrupt_handler(get_handler_descriptor(16, false));
    idt.add_interrupt_handler(get_handler_descriptor(17, true));
    idt.add_interrupt_handler(get_handler_descriptor(18, false));
    idt.add_interrupt_handler(get_handler_descriptor(19, false));
    idt.add_interrupt_handler(get_handler_descriptor(20, false));
    idt.add_interrupt_handler(get_handler_descriptor(21, false));
    idt.add_interrupt_handler(get_handler_descriptor(22, false));
    idt.add_interrupt_handler(get_handler_descriptor(23, false));
    idt.add_interrupt_handler(get_handler_descriptor(24, false));
    idt.add_interrupt_handler(get_handler_descriptor(25, false));
    idt.add_interrupt_handler(get_handler_descriptor(26, false));
    idt.add_interrupt_handler(get_handler_descriptor(27, false));
    idt.add_interrupt_handler(get_handler_descriptor(28, false));
    idt.add_interrupt_handler(get_handler_descriptor(29, false));
    idt.add_interrupt_handler(get_handler_descriptor(30, false));
    idt.add_interrupt_handler(get_handler_descriptor(31, false));
    idt.add_interrupt_handler(get_handler_descriptor(32, false));
    idt.add_interrupt_handler(get_handler_descriptor(33, false));
    idt.add_interrupt_handler(get_handler_descriptor(34, false));
    idt.add_interrupt_handler(get_handler_descriptor(35, false));
    idt.add_interrupt_handler(get_handler_descriptor(36, false));
    idt.add_interrupt_handler(get_handler_descriptor(37, false));
    idt.add_interrupt_handler(get_handler_descriptor(38, false));
    idt.add_interrupt_handler(get_handler_descriptor(39, false));
    idt.add_interrupt_handler(get_handler_descriptor(40, false));
    idt.add_interrupt_handler(get_handler_descriptor(41, false));
    idt.add_interrupt_handler(get_handler_descriptor(42, false));
    idt.add_interrupt_handler(get_handler_descriptor(43, false));
    idt.add_interrupt_handler(get_handler_descriptor(44, false));
    idt.add_interrupt_handler(get_handler_descriptor(45, false));
    idt.add_interrupt_handler(get_handler_descriptor(46, false));
    idt.add_interrupt_handler(get_handler_descriptor(47, false));
    idt.add_interrupt_handler(get_handler_descriptor(48, false));
    idt.add_interrupt_handler(get_handler_descriptor(49, false));
    idt.add_interrupt_handler(get_handler_descriptor(50, false));
    idt.add_interrupt_handler(get_handler_descriptor(51, false));
    idt.add_interrupt_handler(get_handler_descriptor(52, false));
    idt.add_interrupt_handler(get_handler_descriptor(53, false));
    idt.add_interrupt_handler(get_handler_descriptor(54, false));
    idt.add_interrupt_handler(get_handler_descriptor(55, false));
    idt.add_interrupt_handler(get_handler_descriptor(56, false));
    idt.add_interrupt_handler(get_handler_descriptor(57, false));
    idt.add_interrupt_handler(get_handler_descriptor(58, false));
    idt.add_interrupt_handler(get_handler_descriptor(59, false));
    idt.add_interrupt_handler(get_handler_descriptor(60, false));
    idt.add_interrupt_handler(get_handler_descriptor(61, false));
    idt.add_interrupt_handler(get_handler_descriptor(62, false));
    idt.add_interrupt_handler(get_handler_descriptor(63, false));
    idt.add_interrupt_handler(get_handler_descriptor(64, false));
    idt.add_interrupt_handler(get_handler_descriptor(65, false));
    idt.add_interrupt_handler(get_handler_descriptor(66, false));
    idt.add_interrupt_handler(get_handler_descriptor(67, false));
    idt.add_interrupt_handler(get_handler_descriptor(68, false));
    idt.add_interrupt_handler(get_handler_descriptor(69, false));
    idt.add_interrupt_handler(get_handler_descriptor(70, false));
    idt.add_interrupt_handler(get_handler_descriptor(71, false));
    idt.add_interrupt_handler(get_handler_descriptor(72, false));
    idt.add_interrupt_handler(get_handler_descriptor(73, false));
    idt.add_interrupt_handler(get_handler_descriptor(74, false));
    idt.add_interrupt_handler(get_handler_descriptor(75, false));
    idt.add_interrupt_handler(get_handler_descriptor(76, false));
    idt.add_interrupt_handler(get_handler_descriptor(77, false));
    idt.add_interrupt_handler(get_handler_descriptor(78, false));
    idt.add_interrupt_handler(get_handler_descriptor(79, false));
    idt.add_interrupt_handler(get_handler_descriptor(80, false));
    idt.add_interrupt_handler(get_handler_descriptor(81, false));
    idt.add_interrupt_handler(get_handler_descriptor(82, false));
    idt.add_interrupt_handler(get_handler_descriptor(83, false));
    idt.add_interrupt_handler(get_handler_descriptor(84, false));
    idt.add_interrupt_handler(get_handler_descriptor(85, false));
    idt.add_interrupt_handler(get_handler_descriptor(86, false));
    idt.add_interrupt_handler(get_handler_descriptor(87, false));
    idt.add_interrupt_handler(get_handler_descriptor(88, false));
    idt.add_interrupt_handler(get_handler_descriptor(89, false));
    idt.add_interrupt_handler(get_handler_descriptor(90, false));
    idt.add_interrupt_handler(get_handler_descriptor(91, false));
    idt.add_interrupt_handler(get_handler_descriptor(92, false));
    idt.add_interrupt_handler(get_handler_descriptor(93, false));
    idt.add_interrupt_handler(get_handler_descriptor(94, false));
    idt.add_interrupt_handler(get_handler_descriptor(95, false));
    idt.add_interrupt_handler(get_handler_descriptor(96, false));
    idt.add_interrupt_handler(get_handler_descriptor(97, false));
    idt.add_interrupt_handler(get_handler_descriptor(98, false));
    idt.add_interrupt_handler(get_handler_descriptor(99, false));

    idt.add_interrupt_handler(get_handler_descriptor(100, false));
    idt.add_interrupt_handler(get_handler_descriptor(101, false));
    idt.add_interrupt_handler(get_handler_descriptor(102, false));
    idt.add_interrupt_handler(get_handler_descriptor(103, false));
    idt.add_interrupt_handler(get_handler_descriptor(104, false));
    idt.add_interrupt_handler(get_handler_descriptor(105, false));
    idt.add_interrupt_handler(get_handler_descriptor(106, false));
    idt.add_interrupt_handler(get_handler_descriptor(107, false));
    idt.add_interrupt_handler(get_handler_descriptor(108, false));
    idt.add_interrupt_handler(get_handler_descriptor(109, false));
    idt.add_interrupt_handler(get_handler_descriptor(110, false));
    idt.add_interrupt_handler(get_handler_descriptor(111, false));
    idt.add_interrupt_handler(get_handler_descriptor(112, false));
    idt.add_interrupt_handler(get_handler_descriptor(113, false));
    idt.add_interrupt_handler(get_handler_descriptor(114, false));
    idt.add_interrupt_handler(get_handler_descriptor(115, false));
    idt.add_interrupt_handler(get_handler_descriptor(116, false));
    idt.add_interrupt_handler(get_handler_descriptor(117, false));
    idt.add_interrupt_handler(get_handler_descriptor(118, false));
    idt.add_interrupt_handler(get_handler_descriptor(119, false));
    idt.add_interrupt_handler(get_handler_descriptor(120, false));
    idt.add_interrupt_handler(get_handler_descriptor(121, false));
    idt.add_interrupt_handler(get_handler_descriptor(122, false));
    idt.add_interrupt_handler(get_handler_descriptor(123, false));
    idt.add_interrupt_handler(get_handler_descriptor(124, false));
    idt.add_interrupt_handler(get_handler_descriptor(125, false));
    idt.add_interrupt_handler(get_handler_descriptor(126, false));
    idt.add_interrupt_handler(get_handler_descriptor(127, false));
    idt.add_interrupt_handler(get_handler_descriptor(128, false));
    idt.add_interrupt_handler(get_handler_descriptor(129, false));
    idt.add_interrupt_handler(get_handler_descriptor(130, false));
    idt.add_interrupt_handler(get_handler_descriptor(131, false));
    idt.add_interrupt_handler(get_handler_descriptor(132, false));
    idt.add_interrupt_handler(get_handler_descriptor(133, false));
    idt.add_interrupt_handler(get_handler_descriptor(134, false));
    idt.add_interrupt_handler(get_handler_descriptor(135, false));
    idt.add_interrupt_handler(get_handler_descriptor(136, false));
    idt.add_interrupt_handler(get_handler_descriptor(137, false));
    idt.add_interrupt_handler(get_handler_descriptor(138, false));
    idt.add_interrupt_handler(get_handler_descriptor(139, false));
    idt.add_interrupt_handler(get_handler_descriptor(140, false));
    idt.add_interrupt_handler(get_handler_descriptor(141, false));
    idt.add_interrupt_handler(get_handler_descriptor(142, false));
    idt.add_interrupt_handler(get_handler_descriptor(143, false));
    idt.add_interrupt_handler(get_handler_descriptor(144, false));
    idt.add_interrupt_handler(get_handler_descriptor(145, false));
    idt.add_interrupt_handler(get_handler_descriptor(146, false));
    idt.add_interrupt_handler(get_handler_descriptor(147, false));
    idt.add_interrupt_handler(get_handler_descriptor(148, false));
    idt.add_interrupt_handler(get_handler_descriptor(149, false));
    idt.add_interrupt_handler(get_handler_descriptor(150, false));
    idt.add_interrupt_handler(get_handler_descriptor(151, false));
    idt.add_interrupt_handler(get_handler_descriptor(152, false));
    idt.add_interrupt_handler(get_handler_descriptor(153, false));
    idt.add_interrupt_handler(get_handler_descriptor(154, false));
    idt.add_interrupt_handler(get_handler_descriptor(155, false));
    idt.add_interrupt_handler(get_handler_descriptor(156, false));
    idt.add_interrupt_handler(get_handler_descriptor(157, false));
    idt.add_interrupt_handler(get_handler_descriptor(158, false));
    idt.add_interrupt_handler(get_handler_descriptor(159, false));
    idt.add_interrupt_handler(get_handler_descriptor(160, false));
    idt.add_interrupt_handler(get_handler_descriptor(161, false));
    idt.add_interrupt_handler(get_handler_descriptor(162, false));
    idt.add_interrupt_handler(get_handler_descriptor(163, false));
    idt.add_interrupt_handler(get_handler_descriptor(164, false));
    idt.add_interrupt_handler(get_handler_descriptor(165, false));
    idt.add_interrupt_handler(get_handler_descriptor(166, false));
    idt.add_interrupt_handler(get_handler_descriptor(167, false));
    idt.add_interrupt_handler(get_handler_descriptor(168, false));
    idt.add_interrupt_handler(get_handler_descriptor(169, false));
    idt.add_interrupt_handler(get_handler_descriptor(170, false));
    idt.add_interrupt_handler(get_handler_descriptor(171, false));
    idt.add_interrupt_handler(get_handler_descriptor(172, false));
    idt.add_interrupt_handler(get_handler_descriptor(173, false));
    idt.add_interrupt_handler(get_handler_descriptor(174, false));
    idt.add_interrupt_handler(get_handler_descriptor(175, false));
    idt.add_interrupt_handler(get_handler_descriptor(176, false));
    idt.add_interrupt_handler(get_handler_descriptor(177, false));
    idt.add_interrupt_handler(get_handler_descriptor(178, false));
    idt.add_interrupt_handler(get_handler_descriptor(179, false));
    idt.add_interrupt_handler(get_handler_descriptor(180, false));
    idt.add_interrupt_handler(get_handler_descriptor(181, false));
    idt.add_interrupt_handler(get_handler_descriptor(182, false));
    idt.add_interrupt_handler(get_handler_descriptor(183, false));
    idt.add_interrupt_handler(get_handler_descriptor(184, false));
    idt.add_interrupt_handler(get_handler_descriptor(185, false));
    idt.add_interrupt_handler(get_handler_descriptor(186, false));
    idt.add_interrupt_handler(get_handler_descriptor(187, false));
    idt.add_interrupt_handler(get_handler_descriptor(188, false));
    idt.add_interrupt_handler(get_handler_descriptor(189, false));
    idt.add_interrupt_handler(get_handler_descriptor(190, false));
    idt.add_interrupt_handler(get_handler_descriptor(191, false));
    idt.add_interrupt_handler(get_handler_descriptor(192, false));
    idt.add_interrupt_handler(get_handler_descriptor(193, false));
    idt.add_interrupt_handler(get_handler_descriptor(194, false));
    idt.add_interrupt_handler(get_handler_descriptor(195, false));
    idt.add_interrupt_handler(get_handler_descriptor(196, false));
    idt.add_interrupt_handler(get_handler_descriptor(197, false));
    idt.add_interrupt_handler(get_handler_descriptor(198, false));
    idt.add_interrupt_handler(get_handler_descriptor(199, false));
    idt.add_interrupt_handler(get_handler_descriptor(200, false));

    idt.add_interrupt_handler(get_handler_descriptor(201, false));
    idt.add_interrupt_handler(get_handler_descriptor(202, false));
    idt.add_interrupt_handler(get_handler_descriptor(203, false));
    idt.add_interrupt_handler(get_handler_descriptor(204, false));
    idt.add_interrupt_handler(get_handler_descriptor(205, false));
    idt.add_interrupt_handler(get_handler_descriptor(206, false));
    idt.add_interrupt_handler(get_handler_descriptor(207, false));
    idt.add_interrupt_handler(get_handler_descriptor(208, false));
    idt.add_interrupt_handler(get_handler_descriptor(209, false));
    idt.add_interrupt_handler(get_handler_descriptor(210, false));
    idt.add_interrupt_handler(get_handler_descriptor(211, false));
    idt.add_interrupt_handler(get_handler_descriptor(212, false));
    idt.add_interrupt_handler(get_handler_descriptor(213, false));
    idt.add_interrupt_handler(get_handler_descriptor(214, false));
    idt.add_interrupt_handler(get_handler_descriptor(215, false));
    idt.add_interrupt_handler(get_handler_descriptor(216, false));
    idt.add_interrupt_handler(get_handler_descriptor(217, false));
    idt.add_interrupt_handler(get_handler_descriptor(218, false));
    idt.add_interrupt_handler(get_handler_descriptor(219, false));
    idt.add_interrupt_handler(get_handler_descriptor(220, false));
    idt.add_interrupt_handler(get_handler_descriptor(221, false));
    idt.add_interrupt_handler(get_handler_descriptor(222, false));
    idt.add_interrupt_handler(get_handler_descriptor(223, false));
    idt.add_interrupt_handler(get_handler_descriptor(224, false));
    idt.add_interrupt_handler(get_handler_descriptor(225, false));
    idt.add_interrupt_handler(get_handler_descriptor(226, false));
    idt.add_interrupt_handler(get_handler_descriptor(227, false));
    idt.add_interrupt_handler(get_handler_descriptor(228, false));
    idt.add_interrupt_handler(get_handler_descriptor(229, false));
    idt.add_interrupt_handler(get_handler_descriptor(230, false));
    idt.add_interrupt_handler(get_handler_descriptor(231, false));
    idt.add_interrupt_handler(get_handler_descriptor(232, false));
    idt.add_interrupt_handler(get_handler_descriptor(233, false));
    idt.add_interrupt_handler(get_handler_descriptor(234, false));
    idt.add_interrupt_handler(get_handler_descriptor(235, false));
    idt.add_interrupt_handler(get_handler_descriptor(236, false));
    idt.add_interrupt_handler(get_handler_descriptor(237, false));
    idt.add_interrupt_handler(get_handler_descriptor(238, false));
    idt.add_interrupt_handler(get_handler_descriptor(239, false));
    idt.add_interrupt_handler(get_handler_descriptor(240, false));
    idt.add_interrupt_handler(get_handler_descriptor(241, false));
    idt.add_interrupt_handler(get_handler_descriptor(242, false));
    idt.add_interrupt_handler(get_handler_descriptor(243, false));
    idt.add_interrupt_handler(get_handler_descriptor(244, false));
    idt.add_interrupt_handler(get_handler_descriptor(245, false));
    idt.add_interrupt_handler(get_handler_descriptor(246, false));
    idt.add_interrupt_handler(get_handler_descriptor(247, false));
    idt.add_interrupt_handler(get_handler_descriptor(248, false));
    idt.add_interrupt_handler(get_handler_descriptor(249, false));
    idt.add_interrupt_handler(get_handler_descriptor(250, false));
    idt.add_interrupt_handler(get_handler_descriptor(251, false));
    idt.add_interrupt_handler(get_handler_descriptor(252, false));
    idt.add_interrupt_handler(get_handler_descriptor(253, false));
    idt.add_interrupt_handler(get_handler_descriptor(254, false));
    idt.add_interrupt_handler(get_handler_descriptor(255, false));
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
    install_interrupt_handlers();
    log.debug("Installed interrupt handlers", .{});
    idt.load();
    log.debug("Loaded IDT", .{});
    enable();
    log.debug("Enabled interrupts", .{});
}

pub const Context = struct {
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
};

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

const PageFaultErrorCode = kernel.Bitflag(false, enum(u64) {
    present = 0,
    write = 1,
    user = 2,
    reserved_write = 3,
    instruction_fetch = 4,
    protection_key = 5,
    shadow_stack = 6,
    software_guard_extensions = 15,
});

export fn interrupt_handler(context: *Context) callconv(.C) void {
    interrupts.disable();
    log.debug("Context address: 0x{x}", .{@ptrToInt(context)});
    inline for (std.meta.fields(Context)) |field| {
        log.debug("{s}: 0x{x}", .{ field.name, @field(context, field.name) });
    }

    switch (context.interrupt_number) {
        0x0...0x19 => {
            const exception = @intToEnum(Exception, context.interrupt_number);
            const usermode = context.cs & 3 != 0;
            if (usermode) {
                @panic("usermode not implemented yet");
            } else {
                if (context.cs != @offsetOf(GDT.Table, "code_64")) @panic("invalid cs");
                switch (exception) {
                    .page_fault => {
                        const error_code = PageFaultErrorCode.from_bits(@intCast(u16, context.error_code));
                        log.debug("Error code: {}", .{error_code});
                        unreachable;
                    },
                    else => @panic("ni"),
                }
                log.debug("Exception: {s}", .{@tagName(exception)});
            }
        },
        else => unreachable,
    }

    unreachable;
}

const std = @import("std");

//pub const Context = struct {
//cr2: u64,
//ds: u64,
//fxsave: [512 + 16]u8,
//_check: u64,
//cr8: u64,
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
//flags: u64,
//rsp: u64,
//ss: u64,
//};

pub fn get_handler_descriptor(comptime interrupt_number: u64, comptime has_error_code: bool) IDT.Descriptor {
    kernel.assert(@src(), interrupt_number == IDT.interrupt_i);
    const handler_function = struct {
        pub fn handler() callconv(.Naked) void {
            if (comptime !has_error_code) asm volatile ("push $0");
            asm volatile ("push %[interrupt_number]"
                :
                : [interrupt_number] "i" (interrupt_number),
            );

            asm volatile (
                \\cld
                \\push %%rax
                \\push %%rbx
                \\push %%rcx
                \\push %%rdx
                \\push %%rdi
                \\push %%rsi
                \\push %%rbp
                \\push %%r8
                \\push %%r9
                \\push %%r10
                \\push %%r11
                \\push %%r12
                \\push %%r13
                \\push %%r14
                \\push %%r15
                \\mov %%rsp, %%rdi
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

    const handler_address = @ptrToInt(handler_function);
    return IDT.Descriptor{
        .offset_low = @truncate(u16, handler_address),
        .offset_mid = @truncate(u16, handler_address >> 16),
        .offset_high = @truncate(u32, handler_address >> 32),
        .segment_selector = @offsetOf(GDT.Table, "code_64"), // @TODO: this should change as the GDT selector changes
        .interrupt_stack_table = 0,
        .type = .interrupt,
        .descriptor_privilege_level = 0,
        .present = 1,
    };
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
//}context;
