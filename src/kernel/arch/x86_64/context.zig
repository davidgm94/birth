const Context = @This();

const std = @import("../../../common/std.zig");

const crash = @import("../../crash.zig");
const GDT = @import("gdt.zig");
const registers = @import("registers.zig");
const Thread = @import("../../thread.zig");
const VirtualAddress = @import("../../virtual_address.zig");

const log = std.log.scoped(.Context);
const panic = crash.panic;
const RFLAGS = registers.RFLAGS;
const TODO = crash.TODO;

cr8: u64,
ds: u64,
r15: u64,
r14: u64,
r13: u64,
r12: u64,
r11: u64,
r10: u64,
r9: u64,
r8: u64,
rbp: u64,
rsi: u64,
rdi: u64,
rdx: u64,
rcx: u64,
rbx: u64,
rax: u64,
interrupt_number: u64,
error_code: u64,
rip: u64,
cs: u64,
rflags: u64,
rsp: u64,
ss: u64,

pub fn new(thread: *Thread, entry_point: u64) *Context {
    const kernel_stack = get_kernel_stack(thread);
    const user_stack = get_user_stack(thread);
    const arch_context = from_kernel_stack(kernel_stack);
    thread.kernel_stack = VirtualAddress.new(kernel_stack);
    log.debug("Arch Kernel stack: 0x{x}", .{thread.kernel_stack.value});
    thread.kernel_stack.access(*u64).* = @ptrToInt(thread_terminate_stack);
    // TODO: FPU
    switch (thread.privilege_level) {
        .kernel => {
            arch_context.cs = @offsetOf(GDT.Table, "code_64");
            arch_context.ss = @offsetOf(GDT.Table, "data_64");
            arch_context.ds = @offsetOf(GDT.Table, "data_64");
        },
        .user => {
            arch_context.cs = @offsetOf(GDT.Table, "user_code_64") | 0b11;
            arch_context.ss = @offsetOf(GDT.Table, "user_data") | 0b11;
            arch_context.ds = @offsetOf(GDT.Table, "user_data") | 0b11;
            log.debug("CS: 0x{x}. SS: 0x{x}", .{ arch_context.cs, arch_context.ss });
        },
    }

    arch_context.rflags = RFLAGS.Flags.from_flag(.IF).bits;
    arch_context.rip = entry_point;
    arch_context.rsp = user_stack;
    // TODO: arguments
    arch_context.rdi = 0;

    return arch_context;
}

pub fn get_stack_pointer(arch_context: *Context) u64 {
    return arch_context.rsp;
}

fn get_kernel_stack(thread: *Thread) u64 {
    return thread.kernel_stack_base.value + thread.kernel_stack_size - 8;
}

fn get_user_stack(thread: *Thread) u64 {
    const user_stack_base = if (thread.user_stack_base.value == 0) thread.kernel_stack_base.value else thread.user_stack_base.value;
    const user_stack = thread.user_stack_size - 8 + user_stack_base;
    return user_stack;
}

fn from_kernel_stack(kernel_stack: u64) *Context {
    return @intToPtr(*Context, kernel_stack - @sizeOf(Context));
}

pub fn from_thread(thread: *Thread) *Context {
    return from_kernel_stack(get_kernel_stack(thread));
}

pub fn format(context: *const Context, comptime _: []const u8, _: std.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
    try std.internal_format(writer, "Context address: 0x{x}", .{@ptrToInt(context)});
    inline for (std.fields(Context)) |field| {
        try std.internal_format(writer, "\t{s}: 0x{x}\n", .{ field.name, @field(context, field.name) });
    }
}

pub fn check(arch_context: *Context, src: std.SourceLocation) void {
    var failed = false;
    failed = failed or arch_context.cs > 0x100;
    failed = failed or arch_context.ss > 0x100;
    // TODO: more checking
    if (failed) {
        panic("context check failed: {}", .{arch_context});
        //TODO: kernel.crash("check failed: {s}:{}:{} {s}()", .{ src.file, src.line, src.column, src.fn_name });
        _ = src;
    }
}

fn thread_terminate_stack() callconv(.Naked) void {
    asm volatile (
        \\sub $0x8, %%rsp
        \\jmp thread_terminate
    );
    unreachable;
}

export fn thread_terminate(thread: *Thread) void {
    _ = thread;
    TODO();
}
