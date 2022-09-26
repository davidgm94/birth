const common = @import("common");
const assert = common.assert;
const log = common.log.scoped(.Syscall_x86_64);

const RNU = @import("RNU");
const Thread = RNU.Thread;
const Syscall = RNU.Syscall;

const arch = @import("arch");
const x86_64 = arch.x86_64;
const GDT = x86_64.GDT;
const registers = x86_64.registers;

pub fn enable() void {
    // Enable syscall extensions
    var efer = registers.IA32_EFER.read();
    efer.SCE = true;
    registers.IA32_EFER.write(efer);

    registers.IA32_LSTAR.write(@ptrToInt(&kernel_syscall_entry_point));
    // TODO: figure out what this does
    registers.IA32_FMASK.write(@truncate(u22, ~@as(u64, 1 << 1)));
    // Selectors (kernel64 and user32. Syscall MSRs pick from there the correct register
    const kernel64_code_selector = @offsetOf(GDT.Table, "code_64");
    const user32_code_selector: u32 = @offsetOf(GDT.Table, "user_code_32");
    comptime {
        assert(@offsetOf(GDT.Table, "data_64") == kernel64_code_selector + 8);
        assert(@offsetOf(GDT.Table, "user_data") == user32_code_selector + 8);
        assert(@offsetOf(GDT.Table, "user_code_64") == user32_code_selector + 16);
    }
    const high_32: u64 = kernel64_code_selector | user32_code_selector << 16;
    registers.IA32_STAR.write(high_32 << 32);
    log.debug("Enabled syscalls", .{});
}

pub export fn kernel_syscall_entry_point() callconv(.Naked) void {
    // This function only modifies RSP. The other registers are preserved in user space
    // This sets up the kernel stack before actually starting to run kernel code
    asm volatile (
        \\swapgs
        // Save RFLAGS (R11), next instruction address after sysret (RCX) and user stack (RSP)
        \\mov %%r11, %%r12
        \\mov %%rcx, %%r13
        \\mov %%rsp, %%r14
        // Pass original RCX (4th argument)
        \\mov %%rax, %%rcx
        // Get kernel stack
        \\mov %%gs:[0], %%r15
        \\add %[offset], %%r15
        \\mov (%%r15), %%r15
        \\mov %%r15, %%rbp
        // Use kernel stack
        \\mov %%rbp, %%rsp
        // Call the syscall handler
        \\mov %[handler], %%rax
        \\call *(%%rax)
        // Restore RSP, R11 (RFLAGS) and RCX (RIP after sysret)
        \\mov %%r14, %%rsp
        \\mov %%r12, %%r11
        \\mov %%r13, %%rcx
        // Restore user GS
        \\swapgs
        // Go back to user mode
        \\sysretq
        :
        : [offset] "i" (@intCast(u8, @offsetOf(Thread, "kernel_stack"))),
          [handler] "i" (&Syscall.handler),
    );

    @panic("reached unreachable: syscall handler");
}
