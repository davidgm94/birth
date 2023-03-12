const lib = @import("lib");
const assert = lib.assert;
const Syscall = lib.Syscall;

const user = @import("user");

pub const syscall = user.arch.x86_64.syscall;
