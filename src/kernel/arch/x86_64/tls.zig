const std = @import("../../../common/std.zig");
const Thread = @import("../../thread.zig");
const VirtualAddressSpace = @import("../../virtual_address_space.zig");
const Scheduler = @import("../../scheduler.zig");
const registers = @import("registers.zig");

var my_current_thread: *Thread = undefined;

pub inline fn preset_bsp(current_thread: *Thread) void {
    my_current_thread = current_thread;
    // @ZigBug we need to inttoptr here
    tls_pointers = @intToPtr([*]*Thread, @ptrToInt(&my_current_thread))[0..1];
    preset(0);
}

pub inline fn preset(index: u64) void {
    registers.IA32_GS_BASE.write(@ptrToInt(&tls_pointers[index]));
    registers.IA32_KERNEL_GS_BASE.write(0);
}

var tls_pointers: []*Thread = undefined;

/// This is supposed to be called only by the BSP thread/CPU
pub inline fn allocate_and_setup(virtual_address_space: *VirtualAddressSpace, scheduler: *Scheduler) void {
    const cpu_count = scheduler.cpus.len;
    const bsp_thread = tls_pointers[0];
    std.assert(bsp_thread.cpu.?.is_bootstrap);
    tls_pointers = virtual_address_space.heap.allocator.alloc(*Thread, cpu_count) catch @panic("wtf");
    std.assert(scheduler.all_threads.count == scheduler.thread_buffer.element_count);
    std.assert(scheduler.all_threads.count < Thread.Buffer.Bucket.size);
    for (tls_pointers) |*tp, i| {
        tp.* = &scheduler.thread_buffer.first.?.data[i];
    }
    std.assert(tls_pointers[0] == bsp_thread);
    registers.IA32_GS_BASE.write(@ptrToInt(&tls_pointers[0]));
}

pub inline fn set_current(current_thread: *Thread) void {
    const current_cpu = current_thread.cpu orelse @panic("Wtf");
    tls_pointers[current_cpu.id] = current_thread;
}

pub inline fn get_current() *Thread {
    return asm volatile (
        \\mov %%gs:[0], %[result]
        : [result] "=r" (-> *Thread),
    );
}
