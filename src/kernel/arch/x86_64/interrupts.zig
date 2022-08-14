const interrupts = @This();

const std = @import("../../../common/std.zig");

const Context = @import("context.zig");
const context_switch = @import("context_switch.zig");
const CPU = @import("cpu.zig");
const crash = @import("../../crash.zig");
const kernel = @import("../../kernel.zig");
const registers = @import("registers.zig");
const GDT = @import("gdt.zig");
const IDT = @import("idt.zig");
const PIC = @import("pic.zig");
const PhysicalAddress = @import("../../physical_address.zig");
const TLS = @import("tls.zig");

const PCI = @import("../../../drivers/pci.zig");

const log = std.log.scoped(.interrupts);
const cr8 = registers.cr8;
const panic = crash.panic;
const RFLAGS = registers.RFLAGS;

const use_cr8 = true;
pub inline fn enable() void {
    if (use_cr8) {
        cr8.write(0);
        asm volatile ("sti");
    } else {
        asm volatile ("sti");
    }
    //log.debug("IF=1", .{});
}

pub inline fn disable() void {
    if (use_cr8) {
        cr8.write(0xe);
        asm volatile ("sti");
    } else {
        asm volatile ("cli");
    }
    //log.debug("IF=0", .{});
}

pub inline fn disable_all() void {
    asm volatile ("cli");
}

pub inline fn are_enabled() bool {
    if (use_cr8) {
        const if_set = RFLAGS.read().contains(.IF);
        const cr8_value = cr8.read();
        return if_set and cr8_value == 0;
    } else {
        const if_set = RFLAGS.read().contains(.IF);
        return if_set;
    }
}

pub const Handler = fn () callconv(.Naked) void;

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

pub fn install_interrupt_handlers(idt: *IDT) void {
    for (idt.entries) |*entry, i| {
        const handler = handlers[i];
        entry.* = IDT.Descriptor.from_handler(handler);
    }
}

pub fn init(idt: *IDT) void {
    // Initialize interrupts
    log.debug("Initializing interrupts", .{});
    PIC.disable();
    install_interrupt_handlers(idt);
    log.debug("Installed interrupt handlers", .{});
    idt.load();
    log.debug("Loaded IDT", .{});
    interrupts.enable();
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
        std.assert(@sizeOf(PageFaultErrorCode) == @sizeOf(u16));
    }
};

export fn interrupt_handler(context: *Context) align(0x10) callconv(.C) void {
    if (interrupts.are_enabled()) {
        @panic("interrupts are enabled");
    }

    log.debug("===================== START INT 0x{x} =====================", .{context.interrupt_number});
    const should_swap_gs = @truncate(u2, context.cs) == ~@truncate(u2, registers.cs.read());
    if (should_swap_gs) {
        asm volatile ("swapgs");
    }
    defer {
        if (should_swap_gs) asm volatile ("swapgs");
    }

    if (TLS.get_current().cpu) |current_cpu| {
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
                        const page_fault_address = registers.cr2.read();
                        log.debug("Page fault address: 0x{x}. Error code: {}", .{ page_fault_address, error_code });
                        if (error_code.reserved_write) {
                            @panic("reserved write");
                        }

                        @panic("Unresolvable page fault");
                    },
                    else => panic("{s}", .{@tagName(exception)}),
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
            std.assert(result);
            TLS.get_current().cpu.?.lapic.end_of_interrupt();
        },
        0x80 => {
            log.debug("We are getting a syscall", .{});
            context.debug();
            unreachable;
        },
        else => unreachable,
    }

    context.check(@src());

    if (interrupts.are_enabled()) {
        @panic("interrupts should not be enabled");
    }

    log.debug("===================== END INT 0x{x} =====================", .{context.interrupt_number});
}

pub fn get_handler(comptime interrupt_number: u64) fn handler() align(0x10) callconv(.Naked) void {
    const has_error_code = switch (interrupt_number) {
        8, 10, 11, 12, 13, 14, 17 => true,
        else => false,
    };
    return struct {
        pub fn handler() align(0x10) callconv(.Naked) void {
            if (comptime !has_error_code) asm volatile ("push $0");
            asm volatile ("push %[interrupt_number]"
                :
                : [interrupt_number] "i" (interrupt_number),
            );

            context_switch.prologue();

            asm volatile ("call interrupt_handler");

            context_switch.epilogue();

            @panic("Interrupt epilogue didn't iret properly");
        }
    }.handler;
}

pub const interrupt_vector_msi_start = 0x70;
pub const interrupt_vector_msi_count = 0x40;

pub var msi_handlers: [interrupt_vector_msi_count]HandlerInfo = undefined;

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
        const msi_end = interrupt_vector_msi_start + interrupt_vector_msi_count;
        var msi = interrupt_vector_msi_start;
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

pub const IOAPIC = struct {
    address: PhysicalAddress,
    gsi: u32,
    id: u8,

    pub inline fn read(apic: IOAPIC, register: u32) u32 {
        apic.address.access_kernel([*]volatile u32)[0] = register;
        return apic.address.access_kernel([*]volatile u32)[4];
    }

    pub inline fn write(apic: IOAPIC, register: u32, value: u32) void {
        apic.address.access_kernel([*]volatile u32)[0] = register;
        apic.address.access_kernel([*]volatile u32)[4] = value;
    }
};
pub var ioapic: IOAPIC = undefined;
pub const ISO = struct {
    gsi: u32,
    source_IRQ: u8,
    active_low: bool,
    level_triggered: bool,
};
pub var iso: []ISO = undefined;

fn setup_interrupt_redirection_entry(asked_line: u64) bool {
    // TODO: @Lock
    if (already_setup & (@as(u32, 1) << @intCast(u5, asked_line)) != 0) return true;
    const processor_irq = irq_base + @intCast(u32, asked_line);
    _ = processor_irq;

    var active_low = false;
    var level_triggered = false;
    var line = asked_line;

    for (iso) |override| {
        if (override.source_IRQ == line) {
            line = override.gsi;
            active_low = override.active_low;
            level_triggered = override.level_triggered;
            break;
        }
    }

    if (line >= ioapic.gsi and line < (ioapic.gsi + @truncate(u8, ioapic.read(1) >> 16))) {
        line -= ioapic.gsi;
        const redirection_table_index: u32 = @intCast(u32, line) * 2 + 0x10;
        var redirection_entry = processor_irq;
        if (active_low) redirection_entry |= (1 << 13);
        if (level_triggered) redirection_entry |= (1 << 15);

        ioapic.write(redirection_table_index, 1 << 16);
        std.assert(TLS.get_current().cpu.? == &kernel.scheduler.cpus[0]);
        ioapic.write(redirection_table_index + 1, kernel.scheduler.cpus[0].lapic.id << 24);
        ioapic.write(redirection_table_index, redirection_entry);

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

pub inline fn end(cpu: *CPU) void {
    cpu.lapic.end_of_interrupt();
}
