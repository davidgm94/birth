const common = @import("common");
const syscall = common.arch.x86_64.Syscall.syscall;
export fn _start() callconv(.C) void {
    _ = syscall();
}
