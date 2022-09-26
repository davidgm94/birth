comptime {
    if (common.os != .freestanding) @compileError("This file is only to be imported in the kernel");
}

const common = @import("common");

const RNU = @import("RNU");
const Spinlock = RNU.Spinlock;

const arch = switch (common.cpu.arch) {
    .x86_64 => x86_64,
    else => @compileError("Architecture not supported"),
};

pub const x86_64 = @import("kernel/arch/x86_64.zig");

pub const Context = arch.Context;
pub const context_switch = arch.context_switch;
pub const CPU = arch.CPU;
pub const DefaultWriter = arch.DefaultWriter;
pub const drivers = arch.drivers;
pub const interrupts = arch.interrupts;
pub const PCI = arch.PCI;
pub const TLS = arch.TLS;
pub const VAS = arch.VAS;

pub const page_size = arch.page_size;

pub var max_physical_address_bit: u6 = 0;
pub var writer = common.Writer(DefaultWriter.Context, DefaultWriter.Error, DefaultWriter.write){ .context = DefaultWriter.Context{} };
pub var writer_lock = Spinlock{};
