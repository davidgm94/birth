const common = @import("common");

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
pub const paging = @import("x86_64/paging.zig");
pub const PIC = @import("x86_64/pic.zig");
pub const PCI = @import("x86_64/pci.zig");
pub const RTC = @import("x86_64/rtc.zig");
pub const startup = @import("x86_64/startup.zig");
pub const Syscall = @import("x86_64/syscall.zig");
pub const TLS = @import("x86_64/tls.zig");
pub const TSS = @import("x86_64/tss.zig");

pub const registers = @import("x86_64/registers.zig");

pub const valid_page_sizes = [3]comptime_int{ 0x1000, 0x1000 * 0x200, 0x1000 * 0x200 * 0x200 };
pub const reverse_valid_page_sizes = blk: {
    var reverse = valid_page_sizes;
    common.std.mem.reverse(@TypeOf(valid_page_sizes[0]), &reverse);
    break :blk reverse;
};
pub const page_size = valid_page_sizes[0];
pub const reasonable_page_size = valid_page_sizes[1];

pub fn page_shifter(comptime asked_page_size: comptime_int) comptime_int {
    return @ctz(@as(u32, asked_page_size));
}
