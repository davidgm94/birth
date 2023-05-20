const lib = @import("lib");
const assert = lib.assert;

pub const RFLAGS = packed struct(u64) {
    CF: bool = false,
    reserved0: bool = true,
    PF: bool = false,
    reserved1: bool = false,
    AF: bool = false,
    reserved2: bool = false,
    ZF: bool = false,
    SF: bool = false,
    TF: bool = false,
    IF: bool = false,
    DF: bool = false,
    OF: bool = false,
    IOPL: u2 = 0,
    NT: bool = false,
    reserved3: bool = false,
    RF: bool = false,
    VM: bool = false,
    AC: bool = false,
    VIF: bool = false,
    VIP: bool = false,
    ID: bool = false,
    reserved4: u10 = 0,
    reserved5: u32 = 0,

    comptime {
        assert(@sizeOf(RFLAGS) == @sizeOf(u64));
        assert(@bitSizeOf(RFLAGS) == @bitSizeOf(u64));
    }

    pub inline fn read() RFLAGS {
        return asm volatile (
            \\pushfq
            \\pop %[flags]
            : [flags] "=r" (-> RFLAGS),
            :
            : "memory"
        );
    }

    pub fn user(rflags: RFLAGS) RFLAGS {
        return RFLAGS{
            .IF = true,
            .CF = rflags.CF,
            .PF = rflags.PF,
            .AF = rflags.AF,
            .ZF = rflags.ZF,
            .SF = rflags.SF,
            .DF = rflags.DF,
            .OF = rflags.OF,
        };
    }
};

pub const SimpleRegister = enum {
    rax,
    rbx,
    rcx,
    rdx,
    rbp,
    rsp,
    rsi,
    rdi,
    r8,
    r9,
    r10,
    r11,
    r12,
    r13,
    r14,
    r15,

    gs,
    cs,

    dr0,
    dr1,
    dr2,
    dr3,
    dr4,
    dr5,
    dr6,
    dr7,

    cr2,
    cr8,
};

pub fn SimpleR64(comptime Register: SimpleRegister) type {
    return struct {
        pub inline fn read() u64 {
            return switch (Register) {
                .rax => asm volatile ("mov %rax, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .rbx => asm volatile ("mov %rbx, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .rcx => asm volatile ("mov %rcx, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .rdx => asm volatile ("mov %rdx, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .rbp => asm volatile ("mov %rbp, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .rsp => asm volatile ("mov %rsp, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .rsi => asm volatile ("mov %rsi, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .rdi => asm volatile ("mov %rdi, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .r8 => asm volatile ("mov %r8, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .r9 => asm volatile ("mov %r9, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .r10 => asm volatile ("mov %r10, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .r11 => asm volatile ("mov %r11, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .r12 => asm volatile ("mov %r12, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .r13 => asm volatile ("mov %r13, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .r14 => asm volatile ("mov %r14, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .r15 => asm volatile ("mov %r15, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .gs => asm volatile ("mov %gs, %[result]"
                    : [result] "=r" (-> u64),
                    :
                    : "memory"
                ),
                .cs => asm volatile ("mov %cs, %[result]"
                    : [result] "=r" (-> u64),
                    :
                    : "memory"
                ),
                .dr0 => asm volatile ("mov %dr0, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .dr1 => asm volatile ("mov %dr1, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .dr2 => asm volatile ("mov %dr2, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .dr3 => asm volatile ("mov %dr3, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .dr4 => asm volatile ("mov %dr4, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .dr5 => asm volatile ("mov %dr5, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .dr6 => asm volatile ("mov %dr6, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .dr7 => asm volatile ("mov %dr7, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .cr2 => asm volatile ("mov %cr2, %[result]"
                    : [result] "=r" (-> u64),
                    :
                    : "memory"
                ),
                .cr8 => asm volatile ("mov %cr8, %[result]"
                    : [result] "=r" (-> u64),
                    :
                    : "memory"
                ),
            };
        }

        pub inline fn write(value: u64) void {
            switch (Register) {
                .rax => asm volatile ("mov %[in], %rax"
                    :
                    : [in] "r" (value),
                ),
                .rbx => asm volatile ("mov %[in], %rbx"
                    :
                    : [in] "r" (value),
                ),
                .rcx => asm volatile ("mov %[in], %rcx"
                    :
                    : [in] "r" (value),
                ),
                .rdx => asm volatile ("mov %[in], %rdx"
                    :
                    : [in] "r" (value),
                ),
                .rbp => asm volatile ("mov %[in], %rbp"
                    :
                    : [in] "r" (value),
                ),
                .rsp => asm volatile ("mov %[in], %rsp"
                    :
                    : [in] "r" (value),
                ),
                .rsi => asm volatile ("mov %[in], %rsi"
                    :
                    : [in] "r" (value),
                ),
                .rdi => asm volatile ("mov %[in], %rdi"
                    :
                    : [in] "r" (value),
                ),
                .r8 => asm volatile ("mov %[in], %r8"
                    :
                    : [in] "r" (value),
                ),
                .r9 => asm volatile ("mov %[in], %r9"
                    :
                    : [in] "r" (value),
                ),
                .r10 => asm volatile ("mov %[in], %r10"
                    :
                    : [in] "r" (value),
                ),
                .r11 => asm volatile ("mov %[in], %r11"
                    :
                    : [in] "r" (value),
                ),
                .r12 => asm volatile ("mov %[in], %r12"
                    :
                    : [in] "r" (value),
                ),
                .r13 => asm volatile ("mov %[in], %r13"
                    :
                    : [in] "r" (value),
                ),
                .r14 => asm volatile ("mov %[in], %r14"
                    :
                    : [in] "r" (value),
                ),
                .r15 => asm volatile ("mov %[in], %r15"
                    :
                    : [in] "r" (value),
                ),
                .gs => asm volatile ("mov %[in], %gs"
                    :
                    : [in] "r" (value),
                    : "memory"
                ),
                .cs => asm volatile ("mov %[in], %cs"
                    :
                    : [in] "r" (value),
                    : "memory"
                ),
                .dr0 => asm volatile ("mov %[in], %dr0"
                    :
                    : [in] "r" (value),
                ),
                .dr1 => asm volatile ("mov %[in], %dr1"
                    :
                    : [in] "r" (value),
                ),
                .dr2 => asm volatile ("mov %[in], %dr2"
                    :
                    : [in] "r" (value),
                ),
                .dr3 => asm volatile ("mov %[in], %dr3"
                    :
                    : [in] "r" (value),
                ),
                .dr4 => asm volatile ("mov %[in], %dr4"
                    :
                    : [in] "r" (value),
                ),
                .dr5 => asm volatile ("mov %[in], %dr5"
                    :
                    : [in] "r" (value),
                ),
                .dr6 => asm volatile ("mov %[in], %dr6"
                    :
                    : [in] "r" (value),
                ),
                .dr7 => asm volatile ("mov %[in], %dr7"
                    :
                    : [in] "r" (value),
                ),
                .cr2 => asm volatile ("mov %[in], %cr2"
                    :
                    : [in] "r" (value),
                    : "memory"
                ),
                .cr8 => asm volatile ("mov %[in], %cr8"
                    :
                    : [in] "r" (value),
                    : "memory"
                ),
            }
        }
    };
}

pub const ComplexRegister = enum { cr0, cr3, cr4 };

pub const rax = SimpleR64(.rax);
pub const rbx = SimpleR64(.rbx);
pub const rcx = SimpleR64(.rcx);
pub const rdx = SimpleR64(.rdx);
pub const rbp = SimpleR64(.rbp);
pub const rsp = SimpleR64(.rsp);
pub const rsi = SimpleR64(.rsi);
pub const rdi = SimpleR64(.rdi);
pub const r8 = SimpleR64(.r8);
pub const r9 = SimpleR64(.r9);
pub const r10 = SimpleR64(.r10);
pub const r11 = SimpleR64(.r11);
pub const r12 = SimpleR64(.r12);
pub const r13 = SimpleR64(.r13);
pub const r14 = SimpleR64(.r14);
pub const r15 = SimpleR64(.r15);

pub const gs = SimpleR64(.gs);
pub const cs = SimpleR64(.cs);

pub const dr0 = SimpleR64(.dr0);
pub const dr1 = SimpleR64(.dr1);
pub const dr2 = SimpleR64(.dr2);
pub const dr3 = SimpleR64(.dr3);
pub const dr4 = SimpleR64(.dr4);
pub const dr5 = SimpleR64(.dr5);
pub const dr6 = SimpleR64(.dr6);
pub const dr7 = SimpleR64(.dr7);
