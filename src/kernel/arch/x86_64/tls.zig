const common = @import("common");
const log = common.log.scoped(.TLS);

const RNU = @import("RNU");
const Process = RNU.Process;
const Scheduler = RNU.Scheduler;
const Thread = RNU.Thread;

const arch = @import("arch");
const x86_64 = arch.x86_64;
const CPU = x86_64.CPU;
const registers = x86_64.registers;

var my_current_thread: *Thread = undefined;

pub inline fn preset_bsp(scheduler: *Scheduler, thread: *Thread, process: *Process, cpu: *CPU) void {
    my_current_thread = thread;
    process.type = .kernel;
    thread.process = process;
    // @ZigBug we need to inttoptr here
    scheduler.current_threads = @intToPtr([*]*Thread, @ptrToInt(&my_current_thread))[0..1];
    preset(scheduler, cpu);
    set_current(scheduler, thread, cpu);
}

pub inline fn preset(scheduler: *Scheduler, cpu: *CPU) void {
    registers.IA32_GS_BASE.write(@ptrToInt(&scheduler.current_threads[cpu.id]));
    registers.IA32_KERNEL_GS_BASE.write(0);
}

pub inline fn set_current(scheduler: *Scheduler, thread: *Thread, cpu: *CPU) void {
    scheduler.current_threads[cpu.id] = thread;
    thread.cpu = cpu;
    log.debug("Setting current thread #{}", .{thread.id});
}

pub inline fn get_current() *Thread {
    const thread = asm volatile (
        \\mov %%gs:[0], %[result]
        : [result] "=r" (-> *Thread),
    );

    return thread;
}
