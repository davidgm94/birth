const lib = @import("lib");
const assert = lib.assert;
const rise = @import("rise");

pub const UserScheduler = extern struct {
    generic: rise.UserScheduler,
    disabled_save_area: RegisterArena,
};

pub const RegisterArena = extern struct {
    fpu: FPU align(lib.arch.stack_alignment),
    registers: rise.arch.Registers,

    pub fn contextSwitch(register_arena: *align(lib.arch.stack_alignment) const RegisterArena) noreturn {
        assert(lib.isAligned(@intFromPtr(register_arena), lib.arch.stack_alignment));
        //lib.log.debug("ASDASD: {}", .{register_arena});
        register_arena.fpu.load();
        register_arena.registers.restore();
    }
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
            : [registers] "{rdi}" (registers),
              [ss] "i" (rise.arch.user_data_selector),
              [cs] "i" (rise.arch.user_code_selector),
            : "memory"
        );

        unreachable;
    }
};

pub const FPU = extern struct {
    fcw: u16,
    fsw: u16,
    ftw: u8,
    reserved: u8 = 0,
    fop: u16,
    fpu_ip1: u32,
    fpu_ip2: u16,
    reserved0: u16 = 0,
    fpu_dp1: u32,
    fpu_dp2: u16,
    reserved1: u16 = 0,
    mxcsr: u32,
    mxcsr_mask: u32,
    st: [8][2]u64,
    xmm: [16][2]u64,
    reserved2: [12]u64 = .{0} ** 12,

    pub inline fn load(fpu: *align(lib.arch.stack_alignment) const FPU) void {
        assert(@intFromPtr(fpu) % lib.arch.stack_alignment == 0);
        asm volatile (
            \\fxrstor %[fpu]
            :
            : [fpu] "*p" (fpu),
            : "memory"
        );
    }
};

pub const user_code_selector = 0x43;
pub const user_data_selector = 0x3b;

pub inline fn syscall(options: rise.syscall.Options, arguments: rise.syscall.Arguments) rise.syscall.Result {
    var first: rise.syscall.Result.Rise.First = undefined;
    var second: rise.syscall.Result.Rise.Second = undefined;
    asm volatile (
        \\syscall
        : [rax] "={rax}" (first),
          [rdx] "={rdx}" (second),
        : [options] "{rax}" (options),
          [arg0] "{rdi}" (arguments[0]),
          [arg1] "{rsi}" (arguments[1]),
          [arg2] "{rdx}" (arguments[2]),
          [arg3] "{r10}" (arguments[3]),
          [arg4] "{r8}" (arguments[4]),
          [arg5] "{r9}" (arguments[5]),
        : "rcx", "r11", "rsp", "memory"
    );

    return .{
        .rise = .{
            .first = first,
            .second = second,
        },
    };
}
