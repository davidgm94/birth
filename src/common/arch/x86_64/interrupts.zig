const kernel = @import("root");
const common = @import("../../../common.zig");

const x86_64 = common.arch.x86_64;
const PIC = x86_64.PIC;
const IDT = x86_64.IDT;
const GDT = x86_64.GDT;
const PCI = @import("../../../drivers/pci.zig");

const interrupts = @This();
const Context = x86_64.Context;

const TODO = common.TODO;
const Thread = common.Thread;
const Virtual = kernel.Virtual;
const log = common.log.scoped(.interrupts);
const Handler = fn () callconv(.Naked) void;

pub fn install_interrupt_handlers(idt: *IDT) void {
    idt.entries[0] = get_handler_descriptor(0, false);
    idt.entries[1] = get_handler_descriptor(1, false);
    idt.entries[2] = get_handler_descriptor(2, false);
    idt.entries[3] = get_handler_descriptor(3, false);
    idt.entries[4] = get_handler_descriptor(4, false);
    idt.entries[5] = get_handler_descriptor(5, false);
    idt.entries[6] = get_handler_descriptor(6, false);
    idt.entries[7] = get_handler_descriptor(7, false);
    idt.entries[8] = get_handler_descriptor(8, true);
    idt.entries[9] = get_handler_descriptor(9, false);
    idt.entries[10] = get_handler_descriptor(10, true);
    idt.entries[11] = get_handler_descriptor(11, true);
    idt.entries[12] = get_handler_descriptor(12, true);
    idt.entries[13] = get_handler_descriptor(13, true);
    idt.entries[14] = get_handler_descriptor(14, true);
    idt.entries[15] = get_handler_descriptor(15, false);
    idt.entries[16] = get_handler_descriptor(16, false);
    idt.entries[17] = get_handler_descriptor(17, true);
    idt.entries[18] = get_handler_descriptor(18, false);
    idt.entries[19] = get_handler_descriptor(19, false);
    idt.entries[20] = get_handler_descriptor(20, false);
    idt.entries[21] = get_handler_descriptor(21, false);
    idt.entries[22] = get_handler_descriptor(22, false);
    idt.entries[23] = get_handler_descriptor(23, false);
    idt.entries[24] = get_handler_descriptor(24, false);
    idt.entries[25] = get_handler_descriptor(25, false);
    idt.entries[26] = get_handler_descriptor(26, false);
    idt.entries[27] = get_handler_descriptor(27, false);
    idt.entries[28] = get_handler_descriptor(28, false);
    idt.entries[29] = get_handler_descriptor(29, false);
    idt.entries[30] = get_handler_descriptor(30, false);
    idt.entries[31] = get_handler_descriptor(31, false);
    idt.entries[32] = get_handler_descriptor(32, false);
    idt.entries[33] = get_handler_descriptor(33, false);
    idt.entries[34] = get_handler_descriptor(34, false);
    idt.entries[35] = get_handler_descriptor(35, false);
    idt.entries[36] = get_handler_descriptor(36, false);
    idt.entries[37] = get_handler_descriptor(37, false);
    idt.entries[38] = get_handler_descriptor(38, false);
    idt.entries[39] = get_handler_descriptor(39, false);
    idt.entries[40] = get_handler_descriptor(40, false);
    idt.entries[41] = get_handler_descriptor(41, false);
    idt.entries[42] = get_handler_descriptor(42, false);
    idt.entries[43] = get_handler_descriptor(43, false);
    idt.entries[44] = get_handler_descriptor(44, false);
    idt.entries[45] = get_handler_descriptor(45, false);
    idt.entries[46] = get_handler_descriptor(46, false);
    idt.entries[47] = get_handler_descriptor(47, false);
    idt.entries[48] = get_handler_descriptor(48, false);
    idt.entries[49] = get_handler_descriptor(49, false);
    idt.entries[50] = get_handler_descriptor(50, false);
    idt.entries[51] = get_handler_descriptor(51, false);
    idt.entries[52] = get_handler_descriptor(52, false);
    idt.entries[53] = get_handler_descriptor(53, false);
    idt.entries[54] = get_handler_descriptor(54, false);
    idt.entries[55] = get_handler_descriptor(55, false);
    idt.entries[56] = get_handler_descriptor(56, false);
    idt.entries[57] = get_handler_descriptor(57, false);
    idt.entries[58] = get_handler_descriptor(58, false);
    idt.entries[59] = get_handler_descriptor(59, false);
    idt.entries[60] = get_handler_descriptor(60, false);
    idt.entries[61] = get_handler_descriptor(61, false);
    idt.entries[62] = get_handler_descriptor(62, false);
    idt.entries[63] = get_handler_descriptor(63, false);
    idt.entries[64] = get_handler_descriptor(64, false);
    idt.entries[65] = get_handler_descriptor(65, false);
    idt.entries[66] = get_handler_descriptor(66, false);
    idt.entries[67] = get_handler_descriptor(67, false);
    idt.entries[68] = get_handler_descriptor(68, false);
    idt.entries[69] = get_handler_descriptor(69, false);
    idt.entries[70] = get_handler_descriptor(70, false);
    idt.entries[71] = get_handler_descriptor(71, false);
    idt.entries[72] = get_handler_descriptor(72, false);
    idt.entries[73] = get_handler_descriptor(73, false);
    idt.entries[74] = get_handler_descriptor(74, false);
    idt.entries[75] = get_handler_descriptor(75, false);
    idt.entries[76] = get_handler_descriptor(76, false);
    idt.entries[77] = get_handler_descriptor(77, false);
    idt.entries[78] = get_handler_descriptor(78, false);
    idt.entries[79] = get_handler_descriptor(79, false);
    idt.entries[80] = get_handler_descriptor(80, false);
    idt.entries[81] = get_handler_descriptor(81, false);
    idt.entries[82] = get_handler_descriptor(82, false);
    idt.entries[83] = get_handler_descriptor(83, false);
    idt.entries[84] = get_handler_descriptor(84, false);
    idt.entries[85] = get_handler_descriptor(85, false);
    idt.entries[86] = get_handler_descriptor(86, false);
    idt.entries[87] = get_handler_descriptor(87, false);
    idt.entries[88] = get_handler_descriptor(88, false);
    idt.entries[89] = get_handler_descriptor(89, false);
    idt.entries[90] = get_handler_descriptor(90, false);
    idt.entries[91] = get_handler_descriptor(91, false);
    idt.entries[92] = get_handler_descriptor(92, false);
    idt.entries[93] = get_handler_descriptor(93, false);
    idt.entries[94] = get_handler_descriptor(94, false);
    idt.entries[95] = get_handler_descriptor(95, false);
    idt.entries[96] = get_handler_descriptor(96, false);
    idt.entries[97] = get_handler_descriptor(97, false);
    idt.entries[98] = get_handler_descriptor(98, false);
    idt.entries[99] = get_handler_descriptor(99, false);

    idt.entries[100] = get_handler_descriptor(100, false);
    idt.entries[101] = get_handler_descriptor(101, false);
    idt.entries[102] = get_handler_descriptor(102, false);
    idt.entries[103] = get_handler_descriptor(103, false);
    idt.entries[104] = get_handler_descriptor(104, false);
    idt.entries[105] = get_handler_descriptor(105, false);
    idt.entries[106] = get_handler_descriptor(106, false);
    idt.entries[107] = get_handler_descriptor(107, false);
    idt.entries[108] = get_handler_descriptor(108, false);
    idt.entries[109] = get_handler_descriptor(109, false);
    idt.entries[110] = get_handler_descriptor(110, false);
    idt.entries[111] = get_handler_descriptor(111, false);
    idt.entries[112] = get_handler_descriptor(112, false);
    idt.entries[113] = get_handler_descriptor(113, false);
    idt.entries[114] = get_handler_descriptor(114, false);
    idt.entries[115] = get_handler_descriptor(115, false);
    idt.entries[116] = get_handler_descriptor(116, false);
    idt.entries[117] = get_handler_descriptor(117, false);
    idt.entries[118] = get_handler_descriptor(118, false);
    idt.entries[119] = get_handler_descriptor(119, false);
    idt.entries[120] = get_handler_descriptor(120, false);
    idt.entries[121] = get_handler_descriptor(121, false);
    idt.entries[122] = get_handler_descriptor(122, false);
    idt.entries[123] = get_handler_descriptor(123, false);
    idt.entries[124] = get_handler_descriptor(124, false);
    idt.entries[125] = get_handler_descriptor(125, false);
    idt.entries[126] = get_handler_descriptor(126, false);
    idt.entries[127] = get_handler_descriptor(127, false);
    idt.entries[128] = get_handler_descriptor(128, false);
    idt.entries[129] = get_handler_descriptor(129, false);
    idt.entries[130] = get_handler_descriptor(130, false);
    idt.entries[131] = get_handler_descriptor(131, false);
    idt.entries[132] = get_handler_descriptor(132, false);
    idt.entries[133] = get_handler_descriptor(133, false);
    idt.entries[134] = get_handler_descriptor(134, false);
    idt.entries[135] = get_handler_descriptor(135, false);
    idt.entries[136] = get_handler_descriptor(136, false);
    idt.entries[137] = get_handler_descriptor(137, false);
    idt.entries[138] = get_handler_descriptor(138, false);
    idt.entries[139] = get_handler_descriptor(139, false);
    idt.entries[140] = get_handler_descriptor(140, false);
    idt.entries[141] = get_handler_descriptor(141, false);
    idt.entries[142] = get_handler_descriptor(142, false);
    idt.entries[143] = get_handler_descriptor(143, false);
    idt.entries[144] = get_handler_descriptor(144, false);
    idt.entries[145] = get_handler_descriptor(145, false);
    idt.entries[146] = get_handler_descriptor(146, false);
    idt.entries[147] = get_handler_descriptor(147, false);
    idt.entries[148] = get_handler_descriptor(148, false);
    idt.entries[149] = get_handler_descriptor(149, false);
    idt.entries[150] = get_handler_descriptor(150, false);
    idt.entries[151] = get_handler_descriptor(151, false);
    idt.entries[152] = get_handler_descriptor(152, false);
    idt.entries[153] = get_handler_descriptor(153, false);
    idt.entries[154] = get_handler_descriptor(154, false);
    idt.entries[155] = get_handler_descriptor(155, false);
    idt.entries[156] = get_handler_descriptor(156, false);
    idt.entries[157] = get_handler_descriptor(157, false);
    idt.entries[158] = get_handler_descriptor(158, false);
    idt.entries[159] = get_handler_descriptor(159, false);
    idt.entries[160] = get_handler_descriptor(160, false);
    idt.entries[161] = get_handler_descriptor(161, false);
    idt.entries[162] = get_handler_descriptor(162, false);
    idt.entries[163] = get_handler_descriptor(163, false);
    idt.entries[164] = get_handler_descriptor(164, false);
    idt.entries[165] = get_handler_descriptor(165, false);
    idt.entries[166] = get_handler_descriptor(166, false);
    idt.entries[167] = get_handler_descriptor(167, false);
    idt.entries[168] = get_handler_descriptor(168, false);
    idt.entries[169] = get_handler_descriptor(169, false);
    idt.entries[170] = get_handler_descriptor(170, false);
    idt.entries[171] = get_handler_descriptor(171, false);
    idt.entries[172] = get_handler_descriptor(172, false);
    idt.entries[173] = get_handler_descriptor(173, false);
    idt.entries[174] = get_handler_descriptor(174, false);
    idt.entries[175] = get_handler_descriptor(175, false);
    idt.entries[176] = get_handler_descriptor(176, false);
    idt.entries[177] = get_handler_descriptor(177, false);
    idt.entries[178] = get_handler_descriptor(178, false);
    idt.entries[179] = get_handler_descriptor(179, false);
    idt.entries[180] = get_handler_descriptor(180, false);
    idt.entries[181] = get_handler_descriptor(181, false);
    idt.entries[182] = get_handler_descriptor(182, false);
    idt.entries[183] = get_handler_descriptor(183, false);
    idt.entries[184] = get_handler_descriptor(184, false);
    idt.entries[185] = get_handler_descriptor(185, false);
    idt.entries[186] = get_handler_descriptor(186, false);
    idt.entries[187] = get_handler_descriptor(187, false);
    idt.entries[188] = get_handler_descriptor(188, false);
    idt.entries[189] = get_handler_descriptor(189, false);
    idt.entries[190] = get_handler_descriptor(190, false);
    idt.entries[191] = get_handler_descriptor(191, false);
    idt.entries[192] = get_handler_descriptor(192, false);
    idt.entries[193] = get_handler_descriptor(193, false);
    idt.entries[194] = get_handler_descriptor(194, false);
    idt.entries[195] = get_handler_descriptor(195, false);
    idt.entries[196] = get_handler_descriptor(196, false);
    idt.entries[197] = get_handler_descriptor(197, false);
    idt.entries[198] = get_handler_descriptor(198, false);
    idt.entries[199] = get_handler_descriptor(199, false);
    idt.entries[200] = get_handler_descriptor(200, false);

    idt.entries[201] = get_handler_descriptor(201, false);
    idt.entries[202] = get_handler_descriptor(202, false);
    idt.entries[203] = get_handler_descriptor(203, false);
    idt.entries[204] = get_handler_descriptor(204, false);
    idt.entries[205] = get_handler_descriptor(205, false);
    idt.entries[206] = get_handler_descriptor(206, false);
    idt.entries[207] = get_handler_descriptor(207, false);
    idt.entries[208] = get_handler_descriptor(208, false);
    idt.entries[209] = get_handler_descriptor(209, false);
    idt.entries[210] = get_handler_descriptor(210, false);
    idt.entries[211] = get_handler_descriptor(211, false);
    idt.entries[212] = get_handler_descriptor(212, false);
    idt.entries[213] = get_handler_descriptor(213, false);
    idt.entries[214] = get_handler_descriptor(214, false);
    idt.entries[215] = get_handler_descriptor(215, false);
    idt.entries[216] = get_handler_descriptor(216, false);
    idt.entries[217] = get_handler_descriptor(217, false);
    idt.entries[218] = get_handler_descriptor(218, false);
    idt.entries[219] = get_handler_descriptor(219, false);
    idt.entries[220] = get_handler_descriptor(220, false);
    idt.entries[221] = get_handler_descriptor(221, false);
    idt.entries[222] = get_handler_descriptor(222, false);
    idt.entries[223] = get_handler_descriptor(223, false);
    idt.entries[224] = get_handler_descriptor(224, false);
    idt.entries[225] = get_handler_descriptor(225, false);
    idt.entries[226] = get_handler_descriptor(226, false);
    idt.entries[227] = get_handler_descriptor(227, false);
    idt.entries[228] = get_handler_descriptor(228, false);
    idt.entries[229] = get_handler_descriptor(229, false);
    idt.entries[230] = get_handler_descriptor(230, false);
    idt.entries[231] = get_handler_descriptor(231, false);
    idt.entries[232] = get_handler_descriptor(232, false);
    idt.entries[233] = get_handler_descriptor(233, false);
    idt.entries[234] = get_handler_descriptor(234, false);
    idt.entries[235] = get_handler_descriptor(235, false);
    idt.entries[236] = get_handler_descriptor(236, false);
    idt.entries[237] = get_handler_descriptor(237, false);
    idt.entries[238] = get_handler_descriptor(238, false);
    idt.entries[239] = get_handler_descriptor(239, false);
    idt.entries[240] = get_handler_descriptor(240, false);
    idt.entries[241] = get_handler_descriptor(241, false);
    idt.entries[242] = get_handler_descriptor(242, false);
    idt.entries[243] = get_handler_descriptor(243, false);
    idt.entries[244] = get_handler_descriptor(244, false);
    idt.entries[245] = get_handler_descriptor(245, false);
    idt.entries[246] = get_handler_descriptor(246, false);
    idt.entries[247] = get_handler_descriptor(247, false);
    idt.entries[248] = get_handler_descriptor(248, false);
    idt.entries[249] = get_handler_descriptor(249, false);
    idt.entries[250] = get_handler_descriptor(250, false);
    idt.entries[251] = get_handler_descriptor(251, false);
    idt.entries[252] = get_handler_descriptor(252, false);
    idt.entries[253] = get_handler_descriptor(253, false);
    idt.entries[254] = get_handler_descriptor(254, false);
    idt.entries[255] = get_handler_descriptor(255, false);
}

pub fn init(idt: *IDT) void {
    // Initialize interrupts
    log.debug("Initializing interrupts", .{});
    PIC.disable();
    install_interrupt_handlers(idt);
    log.debug("Installed interrupt handlers", .{});
    idt.load();
    log.debug("Loaded IDT", .{});
    x86_64.enable_interrupts();
    log.debug("Enabled interrupts", .{});
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

const PageFaultErrorCode = packed struct {
    present: bool,
    write: bool,
    user: bool,
    reserved_write: bool,
    instruction_fetch: bool,
    protection_key: bool,
    shadow_stack: bool,
    reserved: u8,
    software_guard_extensions: bool,

    comptime {
        common.comptime_assert(@sizeOf(PageFaultErrorCode) == @sizeOf(u16));
    }
};

export fn interrupt_handler(context: *Context) align(0x10) callconv(.C) void {
    if (x86_64.are_interrupts_enabled()) {
        @panic("interrupts are enabled");
    }

    log.debug("===================== START INT 0x{x} =====================", .{context.interrupt_number});
    const should_swap_gs = @truncate(u2, context.cs) == ~@truncate(u2, x86_64.cs.read());
    if (should_swap_gs) {
        asm volatile ("swapgs");
    }
    defer {
        if (should_swap_gs) asm volatile ("swapgs");
    }

    if (x86_64.get_current_thread().cpu) |current_cpu| {
        if (current_cpu.spinlock_count != 0 and context.cr8 != 0xe) {
            @panic("spinlock count bug");
        }
    }

    switch (context.interrupt_number) {
        0x0...0x19 => {
            context.debug();
            const exception = @intToEnum(Exception, context.interrupt_number);
            const usermode = context.cs & 3 != 0;
            if (usermode) {
                @panic("usermode not implemented yet");
            } else {
                if (context.cs != @offsetOf(GDT.Table, "code_64")) @panic("invalid cs");
                switch (exception) {
                    .page_fault => {
                        const error_code_int = @truncate(u16, context.error_code);
                        const error_code = @bitCast(PageFaultErrorCode, error_code_int);
                        const page_fault_address = x86_64.cr2.read();
                        log.debug("Page fault address: 0x{x}. Error code: {}", .{ page_fault_address, error_code });
                        if (error_code.reserved_write) {
                            @panic("reserved write");
                        }

                        @panic("Unresolvable page fault");
                    },
                    else => kernel.crash("{s}", .{@tagName(exception)}),
                }
                log.debug("Exception: {s}", .{@tagName(exception)});
            }
        },
        0x40 => {
            kernel.scheduler.yield(context);
        },
        irq_base...irq_base + 0x20 => {
            // TODO: @Lock
            // TODO: check lines
            const line = context.interrupt_number - irq_base;
            // TODO: dont hard code
            const handler = irq_handlers[0];
            const result = handler.callback(handler.context, line);
            common.runtime_assert(@src(), result);
            x86_64.get_current_thread().cpu.?.lapic.end_of_interrupt();
        },
        0x80 => {
            log.debug("We are getting a syscall", .{});
            context.debug();
            unreachable;
        },
        else => unreachable,
    }

    context.check(@src());

    if (x86_64.are_interrupts_enabled()) {
        @panic("interrupts should not be enabled");
    }

    log.debug("===================== END INT 0x{x} =====================", .{context.interrupt_number});
}

const std = @import("std");

inline fn prologue() void {
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
        \\xor %%rax, %%rax
        \\mov %%ds, %%rax
        \\push %% rax
        \\mov %%cr8, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
    );
}

pub fn get_handler(comptime interrupt_number: u64, comptime has_error_code: bool) fn handler() align(0x10) callconv(.Naked) void {
    return struct {
        pub fn handler() align(0x10) callconv(.Naked) void {
            if (comptime !has_error_code) asm volatile ("push $0");
            asm volatile ("push %[interrupt_number]"
                :
                : [interrupt_number] "i" (interrupt_number),
            );

            prologue();

            asm volatile ("call interrupt_handler");

            epilogue();

            @panic("Interrupt epilogue didn't iret properly");
        }
    }.handler;
}

pub fn get_handler_descriptor(comptime interrupt_number: u64, comptime has_error_code: bool) IDT.Descriptor {
    const handler_function = get_handler(interrupt_number, has_error_code);

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

pub inline fn epilogue() void {
    asm volatile (
        \\cli
        \\pop %%rax
        \\mov %%rax, %%cr8
        \\pop %%rax
        \\mov %%rax, %%ds
        \\mov %%rax, %%es
        \\mov %%rax, %%fs
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rsi
        \\pop %%rdi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );
}

pub var msi_handlers: [x86_64.interrupt_vector_msi_count]HandlerInfo = undefined;

pub const HandlerInfo = struct {
    const Callback = fn (u64, u64) bool;
    callback: Callback,
    context: u64,

    pub fn new(context: anytype, callback: anytype) HandlerInfo {
        return HandlerInfo{
            .callback = @ptrCast(Callback, callback),
            .context = @ptrToInt(context),
        };
    }

    pub fn register_MSI(handler: HandlerInfo) void {
        const msi_end = x86_64.interrupt_vector_msi_start + x86_64.interrupt_vector_msi_count;
        var msi = x86_64.interrupt_vector_msi_start;
        while (msi < msi_end) : (msi += 1) {
            if (msi_handlers[msi].address != 0) continue;
            msi_handlers[msi] = handler;
        }
    }

    pub fn register_IRQ(handler: HandlerInfo, maybe_line: ?u64, pci_device: *PCI.Device) bool {
        // TODO: @Lock
        if (maybe_line) |line| {
            if (line > 0x20) @panic("unexpected irq");
        }

        var found = false;

        // TODO: @Lock
        for (irq_handlers) |*irq_handler| {
            if (irq_handler.context == 0) {
                found = true;
                irq_handler.* = .{
                    .callback = handler.callback,
                    .context = handler.context,
                    .line = pci_device.interrupt_line,
                    .pci_device = pci_device,
                };
                break;
            }
        }

        if (!found) return false;

        if (maybe_line) |line| {
            return setup_interrupt_redirection_entry(line);
        } else {
            return setup_interrupt_redirection_entry(9) and
                setup_interrupt_redirection_entry(10) and
                setup_interrupt_redirection_entry(11);
        }
    }
};

var already_setup: u32 = 0;
const irq_base = 0x50;

fn setup_interrupt_redirection_entry(asked_line: u64) bool {
    // TODO: @Lock
    if (already_setup & (@as(u32, 1) << @intCast(u5, asked_line)) != 0) return true;
    const processor_irq = irq_base + @intCast(u32, asked_line);
    _ = processor_irq;

    var active_low = false;
    var level_triggered = false;
    var line = asked_line;

    for (x86_64.iso) |iso| {
        if (iso.source_IRQ == line) {
            line = iso.gsi;
            active_low = iso.active_low;
            level_triggered = iso.level_triggered;
            break;
        }
    }

    if (line >= x86_64.ioapic.gsi and line < (x86_64.ioapic.gsi + @truncate(u8, x86_64.ioapic.read(1) >> 16))) {
        line -= x86_64.ioapic.gsi;
        const redirection_table_index: u32 = @intCast(u32, line) * 2 + 0x10;
        var redirection_entry = processor_irq;
        if (active_low) redirection_entry |= (1 << 13);
        if (level_triggered) redirection_entry |= (1 << 15);

        x86_64.ioapic.write(redirection_table_index, 1 << 16);
        common.runtime_assert(@src(), x86_64.get_current_thread().cpu.? == &kernel.scheduler.cpus[0]);
        x86_64.ioapic.write(redirection_table_index + 1, kernel.scheduler.cpus[0].lapic.id << 24);
        x86_64.ioapic.write(redirection_table_index, redirection_entry);

        already_setup |= @as(u32, 1) << @intCast(u5, asked_line);
        return true;
    } else {
        @panic("ioapic");
    }
}

var irq_handlers: [0x40]IRQHandler = undefined;

const IRQHandler = struct {
    callback: HandlerInfo.Callback,
    context: u64,
    line: u64,
    pci_device: *PCI.Device,
};
