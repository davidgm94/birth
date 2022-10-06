const common = @import("common");
const assert = common.assert;
const log = common.log.scoped(.TLS);

const RNU = @import("RNU");
const Process = RNU.Process;
const Scheduler = RNU.Scheduler;
const Thread = RNU.Thread;

const kernel = @import("kernel");

const arch = @import("arch");
const x86_64 = arch.x86_64;
const CPU = x86_64.CPU;
const registers = x86_64.registers;

pub inline fn preset_bsp(thread: *Thread, process: *Process, cpu: *CPU) void {
    process.type = .kernel;
    thread.process = process;
    preset(cpu);
    set_current(thread, cpu);
}

pub inline fn preset(cpu: *CPU) void {
    registers.IA32_GS_BASE.write(@ptrToInt(&kernel.memory.cpus.items[cpu.id].current_thread));
    registers.IA32_KERNEL_GS_BASE.write(0);
}

pub inline fn set_current(thread: *Thread, cpu: *CPU) void {
    kernel.memory.cpus.items[cpu.id].current_thread = thread;
    thread.cpu = cpu;
}

pub inline fn get_current() *Thread {
    const thread = asm volatile (
        \\mov %%gs:[0], %[result]
        : [result] "=r" (-> *Thread),
    );

    return thread;
}
