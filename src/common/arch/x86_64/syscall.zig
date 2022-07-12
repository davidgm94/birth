const common = @import("../../../common.zig");
const context = @import("context");
const x86_64 = common.arch.x86_64;

const log = common.log.scoped(.Syscall_x86_64);

pub fn enable() void {
    comptime {
        common.comptime_assert(context.identity == .kernel);
    }
    // Enable syscall extensions
    var efer = x86_64.IA32_EFER.read();
    efer.or_flag(.SCE);
    x86_64.IA32_EFER.write(efer);

    x86_64.IA32_LSTAR.write(@ptrToInt(syscall_entry_point));
    // TODO: figure out what this does
    x86_64.IA32_FMASK.write(@truncate(u22, ~@as(u64, 1 << 1)));
    // Selectors (kernel64 and user32. Syscall MSRs pick from there the correct register
    const kernel64_code_selector = @offsetOf(x86_64.GDT.Table, "code_64");
    const user32_code_selector: u32 = @offsetOf(x86_64.GDT.Table, "user_code_32");
    comptime {
        common.comptime_assert(@offsetOf(x86_64.GDT.Table, "data_64") == kernel64_code_selector + 8);
        common.comptime_assert(@offsetOf(x86_64.GDT.Table, "user_data") == user32_code_selector + 8);
        common.comptime_assert(@offsetOf(x86_64.GDT.Table, "user_code_64") == user32_code_selector + 16);
    }
    const high_32: u64 = kernel64_code_selector | user32_code_selector << 16;
    x86_64.IA32_STAR.write(high_32 << 32);
    log.debug("Enabled syscalls", .{});
}

pub extern fn user_entry_point(arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) callconv(.C) u64;

// INFO: only RSP is handled in the kernel
comptime {
    asm (
        \\.global user_entry_point
        \\user_entry_point:
        \\push %r15
        \\push %r14
        \\push %r13
        \\push %r12
        \\push %rbx
        \\push %rbp
        \\mov %rcx, %rax
        \\syscall
        \\pop %rbp
        \\pop %rbx
        \\pop %r12
        \\pop %r13
        \\pop %r14
        \\pop %r15
        \\ret
    );
}

pub fn syscall_entry_point() callconv(.Naked) noreturn {
    comptime {
        common.comptime_assert(@offsetOf(common.Thread, "kernel_stack") == 8);
    }
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
        // Check if syscall is in range of kernel syscalls
        \\mov %%rdi, %%rax
        \\cmp %[syscall_count], %%rax
        \\jge 0f
        // Multiply the offset by 8 bytes that occupy functions in 64-bit mode
        \\shl $0x03, %%rax
        // Add the base address
        \\add %[handler_base_array], %%rax
        // Call the syscall handler
        \\call *(%%rax)
        // Restore RSP, R11 (RFLAGS) and RCX (RIP after sysret)
        \\mov %%r14, %%rsp
        \\mov %%r12, %%r11
        \\mov %%r13, %%rcx
        // Restore user GS
        \\swapgs
        // Go back to user mode
        \\sysretq
        // Crash if syscall array bounds check failed
        // TODO: we should crash if the index of a syscall is wrong
        \\0:
        \\cli
        \\hlt
        :
        : [offset] "i" (@intCast(u8, @offsetOf(common.Thread, "kernel_stack"))),
          [syscall_count] "i" (common.Syscall.count),
          [handler_base_array] "i" (@ptrToInt(&common.Syscall.kernel.handlers)),
    );

    unreachable;
}
