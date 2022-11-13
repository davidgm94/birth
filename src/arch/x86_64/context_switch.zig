//cosnt reg
//const Thread = privileged.Thread;
//pub inline fn swap_privilege_registers(new_thread: *Thread) void {
//const new_cs_user_bits = @truncate(u2, new_thread.get_context().cs);
//const old_cs_user_bits = @truncate(u2, registers.cs.read());
//const should_swap_gs = new_cs_user_bits == ~old_cs_user_bits;
//if (should_swap_gs) asm volatile ("swapgs");
//}

//pub inline fn set_new_stack(new_stack: u64) void {
//asm volatile ("mov %[in], %%rsp"
//:
//: [in] "r" (new_stack),
//: "nostackssd"
//);
//}

//pub inline fn force_yield() noreturn {
//asm volatile ("int $0x40");
//unreachable;
//}

//pub fn set_new_kernel_stack(thread: *Thread) void {
//const current_cpu = thread.cpu orelse @panic("Wtf");
//current_cpu.tss.rsp[0] = thread.kernel_stack.value;
//}
