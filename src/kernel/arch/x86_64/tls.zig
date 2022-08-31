const std = @import("../../../common/std.zig");
const CPU = @import("cpu.zig");
const Thread = @import("../../thread.zig");
const VirtualAddressSpace = @import("../../virtual_address_space.zig");
const Scheduler = @import("../../scheduler.zig");
const registers = @import("registers.zig");

var my_current_thread: *Thread = undefined;

pub inline fn preset_bsp(scheduler: *Scheduler, thread: *Thread, cpu: *CPU) void {
    my_current_thread = thread;
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
    std.log.scoped(.TLS).debug("Setting current thread #{}", .{thread.id});
}

pub inline fn get_current() *Thread {
    const thread = asm volatile (
        \\mov %%gs:[0], %[result]
        : [result] "=r" (-> *Thread),
    );

    return thread;
}
