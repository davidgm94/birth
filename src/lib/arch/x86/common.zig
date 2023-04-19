pub const CPUID = extern struct {
    eax: u32,
    ebx: u32,
    edx: u32,
    ecx: u32,
};

pub inline fn cpuid(leaf: u32) CPUID {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var edx: u32 = undefined;
    var ecx: u32 = undefined;

    asm volatile (
        \\cpuid
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [edx] "={edx}" (edx),
          [ecx] "={ecx}" (ecx),
        : [leaf] "{eax}" (leaf),
    );

    return CPUID{
        .eax = eax,
        .ebx = ebx,
        .edx = edx,
        .ecx = ecx,
    };
}

pub const Spinlock = enum(u8) {
    released = 0,
    acquired = 1,

    pub inline fn acquire(spinlock: *volatile Spinlock) void {
        asm volatile (
            \\0:
            \\xchgb %[value], %[spinlock]
            \\test %[value], %[value]
            \\jz 2f
            // If not acquire, go to spinloop
            \\1:
            \\pause
            \\cmp %[value], %[spinlock]
            // Retry
            \\jne 0b
            \\jmp 1b
            \\2:
            :
            : [spinlock] "*p" (spinlock),
              [value] "r" (Spinlock.acquired),
            : "memory"
        );
    }

    pub inline fn release(spinlock: *volatile Spinlock) void {
        @atomicStore(Spinlock, spinlock, .released, .Release);
    }
};
