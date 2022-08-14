const Thread = @import("../../thread.zig");
const registers = @import("registers.zig");

inline fn prologue() void {
    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rdi
        \\push %%rsi
        \\push %%rbp
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\xor %%rax, %%rax
        \\mov %%ds, %%rax
        \\push %% rax
        \\mov %%cr8, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
    );
}

pub inline fn epilogue() void {
    asm volatile (
        \\cli
        \\pop %%rax
        \\mov %%rax, %%cr8
        \\pop %%rax
        \\mov %%rax, %%ds
        \\mov %%rax, %%es
        \\mov %%rax, %%fs
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rsi
        \\pop %%rdi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );
}

pub inline fn swap_privilege_registers(new_thread: *Thread) void {
    const new_cs_user_bits = @truncate(u2, new_thread.context.cs);
    const old_cs_user_bits = @truncate(u2, registers.cs.read());
    const should_swap_gs = new_cs_user_bits == ~old_cs_user_bits;
    if (should_swap_gs) asm volatile ("swapgs");
}

pub inline fn set_new_stack(new_stack: u64) void {
    asm volatile ("mov %[in], %%rsp"
        :
        : [in] "r" (new_stack),
        : "nostackssd"
    );
}
