export fn _start() callconv(.C) void {
    asm volatile ("syscall");
}
