const std = @import("../../../common/std.zig");

const GDT = @import("gdt.zig");
const IDT = @import("idt.zig");
const LAPIC = @import("lapic.zig");
const TSS = @import("tss.zig");

lapic: LAPIC,
spinlock_count: u64,
is_bootstrap: bool,
id: u32,
gdt: GDT.Table,
shared_tss: TSS.Struct,
idt: IDT,
