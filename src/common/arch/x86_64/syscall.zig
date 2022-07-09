const kernel = @import("root");
const common = @import("../../../common.zig");
const x86_64 = @import("../x86_64.zig");

const log = common.log.scoped(.Syscall_x86_64);

pub fn enable(syscall_entry_point: fn () callconv(.Naked) void) void {
    x86_64.IA32_LSTAR.write(@ptrToInt(syscall_entry_point));
    // TODO: figure out what this does
    x86_64.IA32_FMASK.write(@truncate(u22, ~@as(u64, 1 << 1)));
    // TODO: figure out what this does
    x86_64.IA32_STAR.write(@offsetOf(x86_64.GDT.Table, "code_64") << 32);
    // TODO: figure out what this does
    var efer = x86_64.IA32_EFER.read();
    efer.or_flag(.SCE);
    x86_64.IA32_EFER.write(efer);
    log.debug("Enabled syscalls", .{});
}

//export fn get_kernel_stack() callconv(.C) u64 {
//log.debug("Getting kernel stack...", .{});
//const current_cpu = get_current_cpu() orelse @panic("foo");
//return current_cpu.current_thread.?.kernel_stack.value;
//}
//pub inline fn get_current_cpu() ?*CPU {
////return @intToPtr(?*kernel.arch.CPU, IA32_GS_BASE.read());
//return asm volatile (
//: [result] "=r" (-> ?*kernel.arch.CPU),
//);
//}
