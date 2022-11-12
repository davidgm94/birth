const privileged = @import("privileged");

const arch = @import("arch");
const x86_64 = arch.x86_64;
const Registers = x86_64.registers.Registers;

const Base = privileged.CoreDirector;
const VirtualAddress = privileged.VirtualAddress;

base: Base,
crit_pc_low: VirtualAddress,
crit_pc_high: VirtualAddress,
ldt_base: VirtualAddress,
ldt_page_count: usize,

enabled_save_area: Registers,
disabled_save_area: Registers,
trap_save_area: Registers,
