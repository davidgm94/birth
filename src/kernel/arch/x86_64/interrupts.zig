const common = @import("common");
const assert = common.assert;
const log = common.log.scoped(.Interrupts);

const RNU = @import("RNU");
const panic = RNU.panic;
const panic_extended = RNU.panic_extended;
const PhysicalAddress = RNU.PhysicalAddress;

const kernel = @import("kernel");

const arch = @import("arch");
const x86_64 = arch.x86_64;
const Context = x86_64.Context;
const context_switch = x86_64.context_switch;
const CPU = x86_64.CPU;
const GDT = x86_64.GDT;
const IDT = x86_64.IDT;
const interrupts = x86_64.interrupts;
const registers = x86_64.registers;
const cr8 = registers.cr8;
const RFLAGS = registers.RFLAGS;
const TLS = x86_64.TLS;

const PCI = @import("../../../drivers/pci.zig");

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
        const if_set = RFLAGS.read().IF;
        const cr8_value = cr8.read();
        return if_set and cr8_value == 0;
    } else {
        const if_set = RFLAGS.read().IF;
        return if_set;
    }
}

//const Exception = enum(u5) {
//divide_by_zero = 0x00,
//debug = 0x01,
//non_maskable_interrupt = 0x2,
//breakpoint = 0x03,
//overflow = 0x04,
//bound_range_exceeded = 0x05,
//invalid_opcode = 0x06,
//device_not_available = 0x07,
//double_fault = 0x08,
//coprocessor_segment_overrun = 0x09,
//invalid_tss = 0x0a,
//segment_not_present = 0x0b,
//stack_segment_fault = 0x0c,
//general_protection_fault = 0x0d,
//page_fault = 0x0e,
//x87_floating_point_exception = 0x10,
//alignment_check = 0x11,
//machine_check = 0x12,
//simd_floating_point_exception = 0x13,
//virtualization_exception = 0x14,
//control_protection_exception = 0x15,
//hypervisor_injection_exception = 0x1c,
//vmm_communication_exception = 0x1d,
//security_exception = 0x1e,
//};

//const PageFaultErrorCode = packed struct {
//present: bool,
//write: bool,
//user: bool,
//reserved_write: bool,
//instruction_fetch: bool,
//protection_key: bool,
//shadow_stack: bool,
//reserved: u8,
//software_guard_extensions: bool,

//comptime {
//assert(@sizeOf(PageFaultErrorCode) == @sizeOf(u16));
//}
//};

//export fn interrupt_handler(context: *Context) align(0x10) callconv(.C) void {
//if (interrupts.are_enabled()) {
//@panic("interrupts are enabled");
//}

//const should_swap_gs = @truncate(u2, context.cs) == ~@truncate(u2, registers.cs.read());
//if (should_swap_gs) {
//asm volatile ("swapgs");
//}

//defer {
//if (should_swap_gs) asm volatile ("swapgs");
//}

//const current_thread = TLS.get_current();
//const current_cpu = current_thread.cpu orelse {
//panic("Thread #{} has no CPU", .{current_thread.id});
//};
//if (current_cpu.spinlock_count != 0 and context.cr8 != 0xe) {
////log.debug("Current cpu spinlock count: {}", .{current_cpu.spinlock_count});
////log.debug("CR8: 0x{x}", .{context.cr8});
//panic("Spinlocks active ({}) while interrupts were enabled\nContext:\n{}\n", .{ current_cpu.spinlock_count, context });
//}

//switch (context.interrupt_number) {
//0x0...0x19 => {
//if (context.interrupt_number == @enumToInt(Exception.non_maskable_interrupt)) {
//while (true) {
//asm volatile ("cli");
////log.err("Another core panicked", .{});
//asm volatile ("pause" ::: "memory");
//asm volatile ("hlt");
//}
//}

//log.debug("Exception context: {}", .{context});
//const exception = @intToEnum(Exception, context.interrupt_number);
//const usermode = context.cs & 3 != 0;
//if (usermode) {
//if (context.cs != @offsetOf(GDT.Table, "user_code_64") | 3) panic_extended("User code CS was supposed to be 0x{x}, was 0x{x}", .{ @offsetOf(GDT.Table, "user_code_64"), context.cs }, context.rip, context.rbp);
//switch (exception) {
//.page_fault => {
//const error_code_int = @truncate(u16, context.error_code);
//const error_code = @bitCast(PageFaultErrorCode, error_code_int);
//const page_fault_address = registers.cr2.read();
//panic_extended("Unresolvable page fault in userspace.\nVirtual address: 0x{x}. Error code: {}", .{ page_fault_address, error_code }, context.rip, context.rbp);
//},
//else => panic_extended("Unhandled exception in user mode: {s}", .{@tagName(exception)}, context.rip, context.rbp),
//}
//} else {
//if (context.cs != @offsetOf(GDT.Table, "code_64")) @panic("invalid cs");

//switch (exception) {
//.page_fault => {
//const error_code_int = @truncate(u16, context.error_code);
//const error_code = @bitCast(PageFaultErrorCode, error_code_int);
//const page_fault_address = registers.cr2.read();
//panic_extended("Unresolvable page fault in the kernel.\nVirtual address: 0x{x}. Error code: {}", .{ page_fault_address, error_code }, context.rip, context.rbp);
//},
//else => panic("{s}", .{@tagName(exception)}),
//}
//}
//},
//0x20...0x2f => {}, // PIC
//0x40 => {
//if (current_cpu.ready) {
//kernel.scheduler.yield(context);
//@panic("we should not return from yield");
//}
//current_cpu.lapic.end_of_interrupt();
//},
//irq_base...irq_base + 0x20 => {
//// TODO: @Lock
//// TODO: check lines
//const line = context.interrupt_number - irq_base;
//// TODO: dont hard code
//const handler = irq_handlers[0];
//const result = handler.callback(handler.context, line);
//assert(result);
//TLS.get_current().cpu.?.lapic.end_of_interrupt();
//},
//0x80 => {
//@panic("Syscalls are not implemented through interrupts");
////log.debug("We are getting a syscall", .{});
////context.debug();
////unreachable;
//},
//else => panic("Unhandled interrupt: {}", .{context}),
//}

//context.check(@src());

//if (interrupts.are_enabled()) {
//@panic("interrupts should not be enabled");
//}
//}

//pub const interrupt_vector_msi_start = 0x70;
//pub const interrupt_vector_msi_count = 0x40;

//pub var msi_handlers: [interrupt_vector_msi_count]HandlerInfo = undefined;

//pub const HandlerInfo = struct {
//const Callback = *const fn (u64, u64) bool;
//callback: Callback,
//context: u64,

//pub fn new(context: anytype, callback: anytype) HandlerInfo {
//return HandlerInfo{
//.callback = @ptrCast(Callback, callback),
//.context = @ptrToInt(context),
//};
//}

//pub fn register_MSI(handler: HandlerInfo) void {
//const msi_end = interrupt_vector_msi_start + interrupt_vector_msi_count;
//var msi = interrupt_vector_msi_start;
//while (msi < msi_end) : (msi += 1) {
//if (msi_handlers[msi].address != 0) continue;
//msi_handlers[msi] = handler;
//}
//}

//pub fn register_IRQ(handler: HandlerInfo, maybe_line: ?u64, pci_device: *PCI.Device) bool {
//// TODO: @Lock
//if (maybe_line) |line| {
//if (line > 0x20) @panic("unexpected irq");
//}

//var found = false;

//// TODO: @Lock
//for (irq_handlers) |*irq_handler| {
//if (irq_handler.context == 0) {
//found = true;
//irq_handler.* = .{
//.callback = handler.callback,
//.context = handler.context,
//.line = pci_device.interrupt_line,
//.pci_device = pci_device,
//};
//break;
//}
//}

//if (!found) return false;

//if (maybe_line) |line| {
//return setup_interrupt_redirection_entry(line);
//} else {
//return setup_interrupt_redirection_entry(9) and
//setup_interrupt_redirection_entry(10) and
//setup_interrupt_redirection_entry(11);
//}
//}
//};

//var already_setup: u32 = 0;
//const irq_base = 0x50;

//pub const IOAPIC = struct {
//address: PhysicalAddress,
//gsi: u32,
//id: u8,

//pub inline fn read(apic: IOAPIC, register: u32) u32 {
//apic.address.to_higher_half_virtual_address().access([*]volatile u32)[0] = register;
//return apic.address.access_kernel([*]volatile u32)[4];
//}

//pub inline fn write(apic: IOAPIC, register: u32, value: u32) void {
//apic.address.access_kernel([*]volatile u32)[0] = register;
//apic.address.access_kernel([*]volatile u32)[4] = value;
//}
//};

//pub var ioapic: IOAPIC = undefined;
//pub const ISO = struct {
//gsi: u32,
//source_IRQ: u8,
//active_low: bool,
//level_triggered: bool,
//};
//pub var iso: []ISO = undefined;

//fn setup_interrupt_redirection_entry(asked_line: u64) bool {
//// TODO: @Lock
//if (already_setup & (@as(u32, 1) << @intCast(u5, asked_line)) != 0) return true;
//const processor_irq = irq_base + @intCast(u32, asked_line);

//var active_low = false;
//var level_triggered = false;
//var line = asked_line;

//for (iso) |override| {
//if (override.source_IRQ == line) {
//line = override.gsi;
//active_low = override.active_low;
//level_triggered = override.level_triggered;
//break;
//}
//}

//if (line >= ioapic.gsi and line < (ioapic.gsi + @truncate(u8, ioapic.read(1) >> 16))) {
//line -= ioapic.gsi;
//const redirection_table_index: u32 = @intCast(u32, line) * 2 + 0x10;
//var redirection_entry = processor_irq;
//if (active_low) redirection_entry |= (1 << 13);
//if (level_triggered) redirection_entry |= (1 << 15);

//ioapic.write(redirection_table_index, 1 << 16);
//assert(TLS.get_current().cpu.? == &kernel.memory.cpus[0]);
//ioapic.write(redirection_table_index + 1, kernel.memory.cpus[0].lapic.id << 24);
//ioapic.write(redirection_table_index, redirection_entry);

//already_setup |= @as(u32, 1) << @intCast(u5, asked_line);
//return true;
//} else {
//@panic("ioapic");
//}
//}

//var irq_handlers: [0x40]IRQHandler = undefined;

//const IRQHandler = struct {
//callback: HandlerInfo.Callback,
//context: u64,
//line: u64,
//pci_device: *PCI.Device,
//};

//pub inline fn end(cpu: *CPU) void {
//if (kernel.config.safe_slow) {
//assert(kernel.virtual_address_space.translate_address(cpu.lapic.address) != null);
//}
//cpu.lapic.end_of_interrupt();
//}

//pub fn send_panic_interrupt_to_all_cpus() void {
//const current_thread = TLS.get_current();
//const panicked_cpu = current_thread.cpu orelse while (true) {
//// TODO: Hang in another way
//asm volatile (
//\\cli
//\\pause
//\\hlt
//);
//};

//var bitset: u2048 = 0;
//assert(kernel.memory.cpus.items.len <= @bitSizeOf(@TypeOf(bitset)));

//for (kernel.memory.cpus.items) |*cpu| {
//if (cpu.id == panicked_cpu.id) continue;
//if (!cpu.ready) {
//bitset |= (@as(@TypeOf(bitset), 1) << @intCast(u11, cpu.id));
//continue;
//}

//const destination = cpu.lapic.id << 24;
//const command = 0x41 | (1 << 14) | 0x400;
//cpu.lapic.write(.ICR_HIGH, destination);
//cpu.lapic.write(.ICR_LOW, command);

//while (cpu.lapic.read(.ICR_LOW) & (1 << 12) != 0) {}
//}

//if (bitset != 0) {
//common.log.scoped(.PANIC).err("CPUs not ready:", .{});

//var i: u64 = 0;
//while (i < @bitSizeOf(@TypeOf(bitset))) : (i += 1) {
//if (bitset & (@as(@TypeOf(bitset), 1) << @intCast(u11, i)) != 0) {
//common.log.scoped(.PANIC).err("{}", .{kernel.memory.cpus.items[i].id});
//}
//}
//}
//}
