const privileged = @import("privileged");

const arch = @import("arch");
const x86_64 = arch.x86_64;
const Registers = x86_64.registers.Registers;

const Base = privileged.CoreDirector;
const VirtualAddress = privileged.VirtualAddress;
