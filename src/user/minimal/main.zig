const common = @import("common");
const thread_exit = common.Syscall.thread_exit;
export fn _start() callconv(.C) void {
    thread_exit(0, 0, 0, 0, 0);
    while (true) {}
}
