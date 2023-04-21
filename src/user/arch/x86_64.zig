const lib = @import("lib");
const assert = lib.assert;
const rise = @import("rise");
const user = @import("user");

const FPU = rise.arch.FPU;
const Registers = rise.arch.Registers;
const RegisterArena = rise.arch.RegisterArena;
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

    pub noinline fn restore(scheduler: *Scheduler, register_arena: *const RegisterArena) noreturn {
        assert(scheduler.common.generic.disabled);
        assert(scheduler.common.generic.has_work);

        assert(register_arena.registers.rip > lib.arch.valid_page_sizes[0]);
        assert(register_arena.registers.rflags.IF and register_arena.registers.rflags.reserved0);

        scheduler.common.generic.disabled = false;

        register_arena.contextSwitch();
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

pub inline fn setInitialState(register_arena: *RegisterArena, entry: VirtualAddress, stack: VirtualAddress, arguments: [6]usize) void {
    assert(stack.value() > lib.arch.valid_page_sizes[0]);
    assert(lib.isAligned(stack.value(), lib.arch.stack_alignment));
    var stack_address = stack;
    // x86_64 ABI
    stack_address.sub(@sizeOf(usize));

    register_arena.registers.rip = entry.value();
    register_arena.registers.rsp = stack_address.value();
    register_arena.registers.rflags = .{ .IF = true };
    register_arena.registers.rdi = arguments[0];
    register_arena.registers.rsi = arguments[1];
    register_arena.registers.rdx = arguments[2];
    register_arena.registers.rcx = arguments[3];
    register_arena.registers.r8 = arguments[4];
    register_arena.registers.r9 = arguments[5];

    register_arena.fpu = lib.zeroes(FPU);
    register_arena.fpu.fcw = 0x037f;
    register_arena.fpu.fcw = 0x1f80;
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
