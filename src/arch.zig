comptime {
    if (common.os != .freestanding and common.os != .uefi) @compileError("This file is only to be imported in the kernel or the bootloader");
}

const common = @import("common");

const RNU = @import("RNU");
const Spinlock = RNU.Spinlock;

const arch = switch (@import("builtin").cpu.arch) {
    .x86_64 => x86_64,
    else => @compileError("Architecture not supported"),
};

pub const x86_64 = @import("kernel/arch/x86_64.zig");

pub const Context = arch.Context;
pub const CoreDirector = arch.CoreDirector;
pub const context_switch = arch.context_switch;
pub const CPU = arch.CPU;
pub const DefaultWriter = arch.DefaultWriter;
pub const dispatch_count = arch.dispatch_count;
pub const drivers = arch.drivers;
pub const interrupts = arch.interrupts;
pub const paging = arch.paging;
pub const PCI = arch.PCI;
pub const startup = arch.startup;
pub const TLS = arch.TLS;

pub const page_size = arch.page_size;
pub const page_shifter = arch.page_shifter;
pub const valid_page_sizes = arch.valid_page_sizes;
pub const reverse_valid_page_sizes = arch.reverse_valid_page_sizes;
pub const reasonable_page_size = arch.reasonable_page_size;

pub var max_physical_address_bit: u6 = 40;
pub var writer = common.Writer(DefaultWriter.Context, DefaultWriter.Error, DefaultWriter.write){ .context = DefaultWriter.Context{} };
pub var writer_lock = Spinlock{};
