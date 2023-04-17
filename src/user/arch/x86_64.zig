const rise = @import("rise");

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
