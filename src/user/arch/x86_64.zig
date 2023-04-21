const lib = @import("lib");
const assert = lib.assert;
const rise = @import("rise");
const user = @import("user");

const Registers = rise.arch.Registers;
const Thread = user.Thread;
const VirtualAddress = user.VirtualAddress;

pub const Scheduler = extern struct {
    common: rise.arch.UserScheduler,
    generic: user.Scheduler,

    pub fn initDisabled(scheduler: *Scheduler) void {
        _ = scheduler;
        // TODO:
        // *set entry points?
        // *set tls registers?
    }

    pub noinline fn restore(scheduler: *Scheduler, registers: *const Registers) noreturn {
        assert(scheduler.common.generic.disabled);
        assert(scheduler.common.generic.has_work);

        assert(registers.rip > lib.arch.valid_page_sizes[0]);
        assert(registers.rflags.IF and registers.rflags.reserved0);

        scheduler.common.generic.disabled = false;

        registers.restore();
    }
};

// CRT0
pub extern fn _start() noreturn;
comptime {
    asm (
        \\.global _start
        \\.extern riseInitializeDisabled
        \\_start:
        \\mov %rdi, %rsp
        \\lea 0x4000(%rdi), %rsp
        \\push %rbp
        \\jmp riseInitializeDisabled
    );
}

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

pub inline fn setInitialState(registers: *Registers, entry: VirtualAddress, stack: VirtualAddress, arguments: [6]usize) void {
    assert(stack.value() > lib.arch.valid_page_sizes[0]);
    assert(lib.isAligned(stack.value(), lib.arch.stack_alignment));
    var stack_address = stack;
    // x86_64 ABI
    stack_address.sub(@sizeOf(usize));

    registers.rip = entry.value();
    registers.rsp = stack_address.value();
    registers.rflags = .{ .IF = true };
    registers.rdi = arguments[0];
    registers.rsi = arguments[1];
    registers.rdx = arguments[2];
    registers.rcx = arguments[3];
    registers.r8 = arguments[4];
    registers.r9 = arguments[5];

    // TODO: FPU
}

pub fn maybeCurrentScheduler() ?*user.Scheduler {
    return asm volatile (
        \\mov %fs:0, %[user_scheduler]
        : [user_scheduler] "=r" (-> ?*user.Scheduler),
        :
        : "memory"
    );
}

pub inline fn currentScheduler() *user.Scheduler {
    const result = maybeCurrentScheduler().?;
    return result;
}
