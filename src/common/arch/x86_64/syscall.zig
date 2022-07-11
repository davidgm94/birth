const common = @import("../../../common.zig");
const context = @import("context");
const x86_64 = common.arch.x86_64;

const log = common.log.scoped(.Syscall_x86_64);

pub fn enable(syscall_entry_point: fn () callconv(.Naked) void) void {
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

pub extern fn syscall(arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) callconv(.C) u64;

// INFO: only RSP is handled in the kernel
comptime {
    asm (
        \\.global syscall
        \\syscall:
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
