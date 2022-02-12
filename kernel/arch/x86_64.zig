const std = @import("std");

pub const GS_base = MSR(0xc0000102);

pub const CPU = struct
{
    id: u64,
};

pub var cpus: [256]CPU = undefined;

pub fn MSR(comptime msr: u32) type
{
    return struct
    {
        pub fn read() callconv(.Inline) u64
        {
            var low: u32 = undefined;
            var high: u32 = undefined;

            asm volatile("rdmsr"
                : [_] "={eax}" (low),
                  [_] "={edx}" (high)
                : [_] "={ecx}" (msr)
            );
            return (@as(u64, high) << 32) | low;
        }

        pub fn write(value: u64) callconv(.Inline) void
        {
            const low = @truncate(u32, value);
            const high = @truncate(u32, value >> 32);

            asm volatile("wrmsr"
                :
                : [_] "{eax}" (low),
                  [_] "{edx}" (high),
                  [_] "{ecx}" (msr)
            );
        }
    };
}

pub fn spin() callconv(.Inline) noreturn
{
    asm volatile("cli");
    while (true)
    {
        std.atomic.spinLoopHint();
    }
}

pub fn set_cpu_local_storage(index: u64) void
{
    GS_base.write(@ptrToInt(&cpus[index]));
}
