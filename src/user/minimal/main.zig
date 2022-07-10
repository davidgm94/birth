const common = @import("common");
const syscall = common.arch.x86_64.Syscall.syscall;
export fn _start() callconv(.C) void {
    const value = syscall(0, 1, 2, 3, 4, 5);
    _ = value;
    while (true) {}
}
