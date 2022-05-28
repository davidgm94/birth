const x86_64 = @import("../x86_64.zig");
const page_size = x86_64.page_size;
const std = @import("std");
const assert = std.debug.assert;
pub const Context = extern struct {
    es: u64,
    ds: u64,
    fx_save: [512 + 16]u8,
    _check: u64,
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rbp: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    rbx: u64,
    rax: u64,
    interrupt_number: u64,
    error_code: u64,
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
};

pub export fn raw_interrupt_handler0() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 0)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $0, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}

pub export fn raw_interrupt_handler1() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 1)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $8, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler2() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 2)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $16, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler3() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 3)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $24, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler4() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 4)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $32, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler5() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 5)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $40, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler6() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 6)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $48, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler7() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 7)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $56, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler8() callconv(.Naked) void {
    asm volatile ("push $0");
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 8)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $64, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler9() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 9)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $72, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler10() callconv(.Naked) void {
    asm volatile ("push $0");
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 10)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $80, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler11() callconv(.Naked) void {
    asm volatile ("push $0");
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 11)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $88, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler12() callconv(.Naked) void {
    asm volatile ("push $0");
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 12)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $96, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler13() callconv(.Naked) void {
    asm volatile ("push $0");
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 13)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $104, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler14() callconv(.Naked) void {
    asm volatile ("push $0");
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 14)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $112, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler15() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 15)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $120, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler16() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 16)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $128, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler17() callconv(.Naked) void {
    asm volatile ("push $0");
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 17)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $136, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler18() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 18)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $144, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler19() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 19)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $152, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler20() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 20)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $160, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler21() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 21)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $168, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler22() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 22)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $176, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler23() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 23)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $184, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler24() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 24)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $192, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler25() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 25)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $200, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler26() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 26)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $208, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler27() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 27)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $216, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler28() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 28)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $224, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler29() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 29)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $232, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler30() callconv(.Naked) void {
    asm volatile ("push $0");
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 30)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $240, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler31() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 31)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $248, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler32() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 32)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $256, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler33() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 33)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $264, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler34() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 34)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $272, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler35() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 35)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $280, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler36() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 36)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $288, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler37() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 37)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $296, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler38() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 38)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $304, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler39() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 39)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $312, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler40() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 40)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $320, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler41() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 41)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $328, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler42() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 42)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $336, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler43() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 43)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $344, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler44() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 44)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $352, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler45() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 45)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $360, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler46() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 46)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $368, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler47() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 47)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $376, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler48() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 48)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $384, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler49() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 49)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $392, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler50() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 50)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $400, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler51() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 51)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $408, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler52() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 52)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $416, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler53() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 53)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $424, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler54() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 54)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $432, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler55() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 55)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $440, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler56() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 56)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $448, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler57() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 57)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $456, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler58() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 58)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $464, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler59() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 59)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $472, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler60() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 60)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $480, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler61() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 61)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $488, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler62() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 62)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $496, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler63() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 63)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $504, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler64() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 64)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $512, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler65() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 65)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $520, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler66() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 66)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $528, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler67() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 67)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $536, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler68() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 68)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $544, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler69() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 69)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $552, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler70() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 70)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $560, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler71() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 71)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $568, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler72() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 72)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $576, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler73() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 73)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $584, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler74() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 74)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $592, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler75() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 75)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $600, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler76() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 76)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $608, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler77() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 77)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $616, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler78() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 78)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $624, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler79() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 79)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $632, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler80() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 80)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $640, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler81() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 81)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $648, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler82() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 82)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $656, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler83() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 83)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $664, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler84() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 84)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $672, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler85() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 85)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $680, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler86() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 86)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $688, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler87() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 87)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $696, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler88() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 88)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $704, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler89() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 89)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $712, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler90() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 90)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $720, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler91() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 91)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $728, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler92() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 92)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $736, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler93() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 93)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $744, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler94() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 94)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $752, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler95() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 95)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $760, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler96() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 96)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $768, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler97() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 97)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $776, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler98() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 98)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $784, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler99() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 99)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $792, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler100() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 100)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $800, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler101() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 101)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $808, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler102() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 102)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $816, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler103() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 103)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $824, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler104() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 104)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $832, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler105() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 105)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $840, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler106() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 106)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $848, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler107() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 107)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $856, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler108() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 108)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $864, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler109() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 109)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $872, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler110() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 110)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $880, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler111() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 111)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $888, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler112() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 112)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $896, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler113() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 113)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $904, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler114() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 114)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $912, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler115() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 115)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $920, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler116() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 116)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $928, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler117() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 117)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $936, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler118() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 118)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $944, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler119() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 119)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $952, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler120() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 120)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $960, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler121() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 121)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $968, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler122() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 122)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $976, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler123() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 123)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $984, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler124() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 124)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $992, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler125() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 125)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1000, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler126() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 126)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1008, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler127() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 127)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1016, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler128() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 128)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1024, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler129() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 129)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1032, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler130() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 130)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1040, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler131() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 131)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1048, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler132() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 132)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1056, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler133() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 133)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1064, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler134() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 134)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1072, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler135() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 135)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1080, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler136() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 136)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1088, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler137() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 137)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1096, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler138() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 138)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1104, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler139() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 139)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1112, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler140() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 140)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1120, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler141() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 141)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1128, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler142() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 142)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1136, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler143() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 143)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1144, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler144() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 144)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1152, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler145() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 145)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1160, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler146() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 146)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1168, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler147() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 147)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1176, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler148() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 148)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1184, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler149() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 149)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1192, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler150() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 150)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1200, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler151() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 151)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1208, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler152() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 152)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1216, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler153() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 153)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1224, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler154() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 154)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1232, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler155() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 155)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1240, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler156() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 156)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1248, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler157() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 157)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1256, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler158() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 158)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1264, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler159() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 159)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1272, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler160() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 160)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1280, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler161() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 161)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1288, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler162() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 162)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1296, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler163() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 163)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1304, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler164() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 164)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1312, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler165() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 165)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1320, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler166() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 166)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1328, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler167() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 167)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1336, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler168() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 168)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1344, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler169() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 169)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1352, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler170() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 170)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1360, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler171() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 171)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1368, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler172() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 172)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1376, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler173() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 173)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1384, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler174() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 174)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1392, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler175() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 175)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1400, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler176() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 176)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1408, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler177() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 177)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1416, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler178() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 178)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1424, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler179() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 179)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1432, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler180() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 180)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1440, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler181() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 181)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1448, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler182() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 182)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1456, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler183() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 183)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1464, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler184() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 184)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1472, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler185() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 185)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1480, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler186() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 186)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1488, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler187() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 187)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1496, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler188() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 188)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1504, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler189() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 189)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1512, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler190() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 190)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1520, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler191() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 191)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1528, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler192() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 192)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1536, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler193() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 193)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1544, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler194() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 194)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1552, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler195() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 195)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1560, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler196() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 196)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1568, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler197() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 197)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1576, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler198() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 198)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1584, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler199() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 199)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1592, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler200() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 200)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1600, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler201() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 201)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1608, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler202() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 202)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1616, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler203() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 203)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1624, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler204() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 204)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1632, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler205() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 205)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1640, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler206() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 206)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1648, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler207() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 207)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1656, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler208() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 208)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1664, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler209() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 209)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1672, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler210() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 210)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1680, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler211() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 211)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1688, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler212() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 212)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1696, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler213() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 213)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1704, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler214() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 214)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1712, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler215() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 215)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1720, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler216() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 216)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1728, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler217() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 217)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1736, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler218() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 218)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1744, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler219() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 219)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1752, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler220() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 220)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1760, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler221() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 221)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1768, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler222() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 222)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1776, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler223() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 223)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1784, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler224() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 224)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1792, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler225() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 225)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1800, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler226() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 226)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1808, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler227() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 227)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1816, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler228() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 228)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1824, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler229() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 229)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1832, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler230() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 230)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1840, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler231() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 231)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1848, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler232() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 232)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1856, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler233() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 233)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1864, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler234() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 234)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1872, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler235() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 235)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1880, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler236() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 236)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1888, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler237() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 237)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1896, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler238() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 238)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1904, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler239() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 239)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1912, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler240() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 240)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1920, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler241() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 241)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1928, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler242() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 242)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1936, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler243() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 243)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1944, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler244() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 244)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1952, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler245() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 245)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1960, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler246() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 246)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1968, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler247() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 247)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1976, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler248() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 248)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1984, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler249() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 249)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $1992, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler250() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 250)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $2000, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler251() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 251)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $2008, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler252() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 252)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $2016, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler253() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 253)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $2024, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler254() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 254)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $2032, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export fn raw_interrupt_handler255() callconv(.Naked) void {
    asm volatile ("push %[vector_number]"
        :
        : [vector_number] "i" (@as(u8, 255)),
    );

    asm volatile (
        \\cld
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov $0x123456789ABCDEF, %%rax
        \\push %%rax
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
        \\fxsave -0x200(%%rsp)
        \\mov %%rbx, %%rsp
        \\sub $0x210, %%rsp
        \\xor %%rax, %%rax
        \\mov %%ds, %%ax
        \\push %%rax
        \\xor %%rax, %%rax
        \\mov %%es, %%rax
        \\push %%rax
        \\mov %%rsp, %%rdi
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rsp 
    );

    asm volatile (
        \\mov $interrupt_handlers, %%rax
        \\add $2040, %%rax
        \\callq *%%rax
    );

    asm volatile (
        \\mov %%rbx, %%rsp
        \\pop %%rbx
        \\mov %%bx, %%es
        \\pop %%rbx
        \\mov %%bx, %%ds
        \\add $0x210, %%rsp
        \\mov %%rsp, %%rbx
        \\and $~0xf, %%rbx
        \\and $~0xf, %%rbx
        \\fxrstor -0x200(%%rbx)
        // @TODO: if this is a new thread, we must initialize the FPU
        \\pop %%rax
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $0x10, %%rsp
        \\iretq
    );

    unreachable;
}
pub export var interrupt_handlers = [256]fn (context: *Context) callconv(.C) void{
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
    unhandled_interrupt,
};
pub export fn unhandled_interrupt(_: *Context) callconv(.C) void {
    while (true) {}
}

pub const IDT = struct {
    pub const Descriptor = packed struct {
        offset_low: u16,
        segment_selector: u16,
        interrupt_stack_table: u3,
        reserved0: u5 = 0,
        type: u4,
        reserved1: u1 = 0, // storage?
        descriptor_privilege_level: u2,
        present: u1,
        offset_mid: u16,
        offset_high: u32,
        reserved2: u32 = 0,
    };

    pub const Register = extern struct {
        limit: u16 = @sizeOf(IDT.Table) - 1,
        address: *IDT.Table,
    };

    comptime {
        assert(@sizeOf(Descriptor) == 16);
    }

    const Table = [256]Descriptor;
    pub var table: IDT.Table align(page_size) = undefined;

    pub fn fill() void {
        table[0] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler0)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler0) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler0) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[1] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler1)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler1) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler1) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[2] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler2)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler2) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler2) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[3] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler3)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler3) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler3) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[4] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler4)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler4) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler4) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[5] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler5)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler5) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler5) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[6] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler6)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler6) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler6) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[7] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler7)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler7) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler7) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[8] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler8)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler8) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler8) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[9] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler9)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler9) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler9) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[10] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler10)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler10) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler10) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[11] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler11)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler11) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler11) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[12] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler12)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler12) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler12) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[13] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler13)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler13) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler13) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[14] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler14)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler14) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler14) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[15] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler15)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler15) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler15) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[16] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler16)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler16) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler16) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[17] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler17)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler17) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler17) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[18] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler18)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler18) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler18) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[19] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler19)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler19) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler19) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[20] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler20)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler20) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler20) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[21] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler21)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler21) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler21) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[22] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler22)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler22) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler22) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[23] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler23)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler23) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler23) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[24] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler24)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler24) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler24) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[25] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler25)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler25) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler25) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[26] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler26)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler26) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler26) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[27] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler27)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler27) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler27) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[28] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler28)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler28) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler28) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[29] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler29)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler29) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler29) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[30] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler30)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler30) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler30) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[31] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler31)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler31) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler31) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[32] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler32)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler32) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler32) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[33] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler33)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler33) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler33) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[34] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler34)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler34) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler34) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[35] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler35)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler35) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler35) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[36] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler36)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler36) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler36) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[37] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler37)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler37) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler37) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[38] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler38)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler38) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler38) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[39] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler39)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler39) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler39) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[40] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler40)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler40) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler40) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[41] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler41)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler41) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler41) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[42] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler42)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler42) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler42) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[43] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler43)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler43) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler43) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[44] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler44)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler44) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler44) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[45] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler45)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler45) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler45) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[46] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler46)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler46) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler46) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[47] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler47)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler47) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler47) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[48] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler48)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler48) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler48) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[49] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler49)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler49) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler49) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[50] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler50)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler50) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler50) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[51] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler51)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler51) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler51) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[52] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler52)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler52) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler52) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[53] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler53)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler53) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler53) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[54] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler54)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler54) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler54) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[55] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler55)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler55) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler55) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[56] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler56)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler56) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler56) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[57] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler57)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler57) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler57) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[58] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler58)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler58) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler58) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[59] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler59)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler59) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler59) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[60] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler60)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler60) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler60) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[61] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler61)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler61) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler61) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[62] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler62)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler62) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler62) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[63] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler63)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler63) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler63) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[64] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler64)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler64) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler64) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[65] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler65)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler65) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler65) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[66] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler66)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler66) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler66) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[67] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler67)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler67) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler67) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[68] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler68)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler68) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler68) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[69] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler69)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler69) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler69) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[70] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler70)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler70) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler70) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[71] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler71)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler71) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler71) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[72] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler72)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler72) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler72) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[73] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler73)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler73) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler73) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[74] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler74)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler74) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler74) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[75] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler75)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler75) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler75) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[76] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler76)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler76) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler76) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[77] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler77)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler77) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler77) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[78] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler78)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler78) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler78) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[79] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler79)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler79) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler79) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[80] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler80)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler80) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler80) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[81] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler81)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler81) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler81) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[82] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler82)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler82) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler82) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[83] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler83)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler83) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler83) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[84] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler84)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler84) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler84) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[85] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler85)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler85) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler85) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[86] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler86)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler86) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler86) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[87] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler87)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler87) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler87) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[88] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler88)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler88) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler88) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[89] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler89)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler89) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler89) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[90] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler90)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler90) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler90) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[91] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler91)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler91) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler91) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[92] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler92)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler92) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler92) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[93] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler93)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler93) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler93) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[94] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler94)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler94) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler94) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[95] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler95)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler95) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler95) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[96] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler96)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler96) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler96) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[97] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler97)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler97) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler97) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[98] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler98)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler98) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler98) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[99] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler99)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler99) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler99) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[100] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler100)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler100) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler100) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[101] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler101)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler101) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler101) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[102] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler102)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler102) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler102) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[103] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler103)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler103) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler103) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[104] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler104)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler104) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler104) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[105] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler105)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler105) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler105) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[106] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler106)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler106) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler106) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[107] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler107)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler107) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler107) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[108] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler108)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler108) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler108) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[109] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler109)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler109) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler109) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[110] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler110)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler110) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler110) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[111] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler111)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler111) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler111) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[112] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler112)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler112) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler112) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[113] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler113)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler113) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler113) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[114] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler114)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler114) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler114) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[115] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler115)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler115) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler115) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[116] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler116)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler116) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler116) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[117] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler117)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler117) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler117) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[118] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler118)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler118) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler118) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[119] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler119)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler119) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler119) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[120] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler120)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler120) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler120) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[121] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler121)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler121) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler121) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[122] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler122)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler122) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler122) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[123] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler123)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler123) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler123) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[124] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler124)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler124) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler124) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[125] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler125)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler125) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler125) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[126] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler126)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler126) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler126) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[127] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler127)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler127) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler127) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[128] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler128)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler128) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler128) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[129] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler129)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler129) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler129) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[130] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler130)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler130) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler130) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[131] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler131)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler131) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler131) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[132] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler132)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler132) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler132) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[133] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler133)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler133) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler133) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[134] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler134)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler134) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler134) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[135] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler135)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler135) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler135) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[136] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler136)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler136) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler136) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[137] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler137)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler137) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler137) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[138] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler138)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler138) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler138) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[139] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler139)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler139) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler139) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[140] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler140)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler140) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler140) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[141] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler141)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler141) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler141) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[142] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler142)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler142) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler142) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[143] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler143)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler143) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler143) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[144] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler144)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler144) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler144) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[145] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler145)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler145) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler145) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[146] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler146)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler146) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler146) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[147] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler147)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler147) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler147) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[148] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler148)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler148) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler148) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[149] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler149)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler149) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler149) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[150] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler150)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler150) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler150) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[151] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler151)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler151) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler151) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[152] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler152)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler152) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler152) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[153] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler153)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler153) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler153) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[154] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler154)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler154) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler154) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[155] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler155)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler155) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler155) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[156] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler156)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler156) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler156) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[157] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler157)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler157) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler157) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[158] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler158)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler158) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler158) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[159] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler159)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler159) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler159) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[160] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler160)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler160) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler160) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[161] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler161)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler161) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler161) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[162] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler162)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler162) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler162) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[163] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler163)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler163) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler163) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[164] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler164)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler164) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler164) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[165] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler165)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler165) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler165) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[166] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler166)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler166) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler166) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[167] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler167)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler167) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler167) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[168] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler168)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler168) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler168) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[169] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler169)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler169) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler169) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[170] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler170)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler170) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler170) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[171] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler171)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler171) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler171) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[172] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler172)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler172) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler172) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[173] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler173)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler173) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler173) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[174] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler174)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler174) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler174) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[175] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler175)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler175) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler175) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[176] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler176)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler176) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler176) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[177] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler177)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler177) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler177) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[178] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler178)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler178) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler178) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[179] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler179)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler179) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler179) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[180] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler180)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler180) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler180) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[181] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler181)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler181) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler181) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[182] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler182)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler182) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler182) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[183] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler183)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler183) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler183) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[184] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler184)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler184) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler184) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[185] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler185)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler185) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler185) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[186] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler186)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler186) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler186) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[187] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler187)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler187) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler187) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[188] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler188)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler188) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler188) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[189] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler189)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler189) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler189) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[190] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler190)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler190) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler190) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[191] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler191)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler191) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler191) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[192] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler192)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler192) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler192) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[193] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler193)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler193) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler193) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[194] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler194)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler194) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler194) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[195] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler195)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler195) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler195) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[196] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler196)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler196) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler196) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[197] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler197)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler197) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler197) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[198] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler198)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler198) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler198) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[199] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler199)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler199) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler199) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[200] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler200)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler200) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler200) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[201] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler201)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler201) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler201) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[202] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler202)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler202) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler202) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[203] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler203)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler203) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler203) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[204] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler204)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler204) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler204) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[205] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler205)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler205) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler205) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[206] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler206)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler206) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler206) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[207] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler207)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler207) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler207) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[208] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler208)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler208) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler208) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[209] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler209)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler209) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler209) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[210] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler210)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler210) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler210) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[211] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler211)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler211) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler211) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[212] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler212)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler212) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler212) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[213] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler213)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler213) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler213) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[214] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler214)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler214) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler214) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[215] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler215)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler215) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler215) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[216] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler216)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler216) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler216) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[217] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler217)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler217) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler217) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[218] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler218)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler218) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler218) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[219] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler219)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler219) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler219) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[220] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler220)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler220) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler220) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[221] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler221)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler221) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler221) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[222] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler222)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler222) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler222) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[223] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler223)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler223) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler223) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[224] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler224)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler224) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler224) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[225] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler225)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler225) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler225) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[226] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler226)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler226) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler226) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[227] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler227)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler227) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler227) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[228] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler228)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler228) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler228) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[229] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler229)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler229) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler229) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[230] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler230)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler230) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler230) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[231] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler231)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler231) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler231) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[232] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler232)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler232) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler232) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[233] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler233)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler233) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler233) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[234] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler234)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler234) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler234) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[235] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler235)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler235) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler235) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[236] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler236)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler236) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler236) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[237] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler237)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler237) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler237) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[238] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler238)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler238) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler238) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[239] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler239)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler239) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler239) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[240] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler240)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler240) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler240) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[241] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler241)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler241) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler241) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[242] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler242)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler242) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler242) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[243] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler243)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler243) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler243) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[244] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler244)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler244) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler244) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[245] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler245)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler245) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler245) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[246] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler246)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler246) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler246) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[247] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler247)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler247) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler247) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[248] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler248)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler248) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler248) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[249] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler249)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler249) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler249) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[250] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler250)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler250) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler250) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[251] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler251)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler251) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler251) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[252] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler252)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler252) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler252) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[253] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler253)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler253) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler253) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[254] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler254)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler254) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler254) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
        table[255] = Descriptor{
            .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler255)),
            .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler255) >> 16),
            .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler255) >> 32),
            .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            .interrupt_stack_table = 0,
            .type = 0xe,
            .descriptor_privilege_level = 0,
            .present = 1,
        };
    }
};
