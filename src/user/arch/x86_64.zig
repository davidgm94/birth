const lib = @import("lib");
const Syscall = lib.Syscall;

pub inline fn syscall(arguments: Syscall.Arguments) usize {
    return asm volatile (
        \\syscall
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (arguments.number),
          [arg0] "{rdi}" (arguments.arguments[0]),
          [arg1] "{rsi}" (arguments.arguments[1]),
          [arg2] "{rdx}" (arguments.arguments[2]),
          [arg3] "{r10}" (arguments.arguments[3]),
          [arg4] "{r8}" (arguments.arguments[4]),
          [arg5] "{r9}" (arguments.arguments[5]),
        : "rcx", "rsp", "memory"
    );
}
