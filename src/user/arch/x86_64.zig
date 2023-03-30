const lib = @import("lib");
const Syscall = lib.Syscall;

const Result = extern struct {
    first: usize,
    second: usize,
};

pub inline fn syscall(options: Syscall.Options, arguments: Syscall.Arguments) Syscall.Result {
    var first: Syscall.Result.Rise.First = undefined;
    var second: Syscall.Result.Rise.Second = undefined;
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
        : "rcx", "rsp", "memory"
    );

    return .{
        .rise = .{
            .first = first,
            .second = second,
        },
    };
}
