const lib = @import("lib");
const rise = @import("rise");

pub const UserScheduler = extern struct {
    generic: rise.UserScheduler,
    disabled_save_area: rise.arch.Registers,
};

pub const Registers = extern struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    syscall_number_or_error_code: u64,
    rip: u64,
    cs: u64,
    rflags: lib.arch.x86_64.registers.RFLAGS,
    rsp: u64,
    ss: u64,
};
