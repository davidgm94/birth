const lib = @import("lib");
const assert = lib.assert;
const Syscall = lib.Syscall;

const user = @import("user");

pub const rawSyscall = user.arch.x86_64.syscall;
