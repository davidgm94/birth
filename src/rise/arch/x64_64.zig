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
    rip: u64,
    rflags: lib.arch.x86_64.registers.RFLAGS,
    rsp: u64,

    pub fn restore(registers: *const Registers) noreturn {
        const fmt = lib.comptimePrint;
        asm volatile (fmt(
                "mov {}(%[registers]), %r15\n\t" ++
                    "mov {}(%[registers]), %r14\n\t" ++
                    "mov {}(%[registers]), %r13\n\t" ++
                    "mov {}(%[registers]), %r12\n\t" ++
                    "mov {}(%[registers]), %rbp\n\t" ++
                    "mov {}(%[registers]), %rbx\n\t" ++
                    "mov {}(%[registers]), %r11\n\t" ++
                    "mov {}(%[registers]), %r10\n\t" ++
                    "mov {}(%[registers]), %r9\n\t" ++
                    "mov {}(%[registers]), %r8\n\t" ++
                    "mov {}(%[registers]), %rax\n\t" ++
                    "mov {}(%[registers]), %rcx\n\t" ++
                    "mov {}(%[registers]), %rdx\n\t" ++
                    "mov {}(%[registers]), %rsi\n\t" ++
                    "pushq %[ss]\n\t" ++
                    "pushq {}(%[registers])\n\t" ++
                    "pushq {}(%[registers])\n\t" ++
                    "pushq %[cs]\n\t" ++
                    "pushq {}(%[registers])\n\t" ++
                    "mov {}(%[registers]), %rdi\n\t" ++
                    "iretq\n\t" ++
                    "1: jmp 1b",

                .{
                    @offsetOf(Registers, "r15"),
                    @offsetOf(Registers, "r14"),
                    @offsetOf(Registers, "r13"),
                    @offsetOf(Registers, "r12"),
                    @offsetOf(Registers, "rbp"),
                    @offsetOf(Registers, "rbx"),
                    @offsetOf(Registers, "r11"),
                    @offsetOf(Registers, "r10"),
                    @offsetOf(Registers, "r9"),
                    @offsetOf(Registers, "r8"),
                    @offsetOf(Registers, "rax"),
                    @offsetOf(Registers, "rcx"),
                    @offsetOf(Registers, "rdx"),
                    @offsetOf(Registers, "rsi"),
                    @offsetOf(Registers, "rsp"),
                    @offsetOf(Registers, "rflags"),
                    @offsetOf(Registers, "rip"),
                    @offsetOf(Registers, "rdi"),
                },
            )
            :
            : [ss] "i" (rise.arch.user_data_selector),
              [registers] "{rdi}" (registers),
              [cs] "i" (rise.arch.user_code_selector),
            : "memory"
        );

        unreachable;
    }
};

pub const user_code_selector = 0x43;
pub const user_data_selector = 0x3b;
