const common = @import("../../../common.zig");
const context = @import("context");
const x86_64 = common.arch.x86_64;

const log = common.log.scoped(.Syscall_x86_64);

pub fn enable(syscall_entry_point: fn () callconv(.Naked) void) void {
    comptime {
        common.comptime_assert(context.identity == .kernel);
    }
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

pub extern fn syscall(arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) callconv(.C) u64;

comptime {
    asm (
    //\\.global syscall
    //\\syscall:
    //\\push %r15
    //\\push %r14
    //\\push %r13
    //\\push %r12
    //\\push %rbx
    //\\push %rbp
    //\\mov %rcx, %rax
    //\\syscall
    //\\pop %rbp
    //\\pop %rbx
    //\\pop %r12
    //\\pop %r13
    //\\pop %r14
    //\\pop %r15
    //\\ret

        \\.global syscall
        \\syscall:
        \\mov %rcx, %rax
        \\syscall
        \\ret
    );
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

