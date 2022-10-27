const RNU = @import("RNU");
const PhysicalAddress = RNU.PhysicalAddress;

pub const APIC = @import("x86_64/apic.zig");
pub const Context = @import("x86_64/context.zig");
pub const context_switch = @import("x86_64/context_switch.zig");
pub const CPU = @import("x86_64/cpu.zig");
pub const CPUID = @import("x86_64/cpuid.zig");
pub const DefaultWriter = @import("x86_64/serial_writer.zig");
pub const DescriptorTable = @import("x86_64/descriptor_table.zig");
pub const Director = @import("x86_64/director.zig");
pub const drivers = @import("x86_64/drivers.zig");
pub const GDT = @import("x86_64/gdt.zig");
pub const IDT = @import("x86_64/idt.zig");
pub const io = @import("x86_64/io.zig");
pub const interrupts = @import("x86_64/interrupts.zig");
pub const LAPIC = @import("x86_64/lapic.zig");
pub const PIC = @import("x86_64/pic.zig");
pub const PCI = @import("x86_64/pci.zig");
pub const Syscall = @import("x86_64/syscall.zig");
pub const TLS = @import("x86_64/tls.zig");
pub const TSS = @import("x86_64/tss.zig");
pub const VAS = @import("x86_64/vas.zig");

pub const registers = @import("x86_64/registers.zig");

pub const valid_page_sizes = [3]comptime_int{ 0x1000, 0x1000 * 0x200, 0x1000 * 0x200 * 0x200 };
pub const page_size = valid_page_sizes[0];
pub const page_shifter = @ctz(@as(u32, page_size));
