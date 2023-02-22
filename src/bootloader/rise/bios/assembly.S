.section .realmode
.code16
.align 0x1000
.global smp_trampoline
.global smp_trampoline_arg_start
.global smp_trampoline_arg_end
.global far_jump_segment
.global gdt32_ds
smp_trampoline:
cli
cld

mov %cs, %ebx
shl $0x4, %ebx

lidtl %cs:(invalid_idt - smp_trampoline)
lgdtl %cs:(arg_gdt_address - smp_trampoline)
leal (protected_mode - smp_trampoline)(%ebx), %eax
movl %eax, %cs:(far_jump_offset - smp_trampoline)
movl $0x11, %eax
movl %eax, %cr0
xorl %eax, %eax
mov %cs:(gdt32_ds - smp_trampoline), %ax
ljmpl *%cs:(far_jump - smp_trampoline)

far_jump:
far_jump_offset: .double 0
// This is supposed to contain 
far_jump_segment: .double 0
gdt32_ds:
.word 0

.code32
protected_mode:
movw %ax, %ds
movw %ax, %es
movw %ax, %fs
movw %ax, %gs
movw %ax, %ss
xorl %eax, %eax
lldtw %ax
xorl %eax, %eax
movl %eax, %cr4

// TODO: Change
// always no x2apic
lea (temporal_stack_top - smp_trampoline)(%ebx), %esp


.align 16

temporal_stack:
.fill 128, 0
temporal_stack_top:

invalid_idt:
.quad 0
.quad 0

.align 8
smp_trampoline_arg_start:
arg_hhdm:
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
arg_cr3:
.byte 0
.byte 0
.byte 0
.byte 0
arg_booted:
.byte 0
arg_options:
.byte 0
arg_gdt_start:
arg_gdt_limit:
.byte 0
.byte 0
arg_gdt_address:
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
.byte 0
smp_trampoline_arg_end:


.code32
.align 0x10
.global interrupt
interrupt:
movb 4(%esp), %al
movb %al, (.interrupt_number)

movl 8(%esp), %eax
movl %eax, (.out_registers)

movl 12(%esp), %eax
movl %eax, (.in_registers)

sgdt [.protected_mode_gdt]
sidt [.protected_mode_idt]
lidt [.real_mode_idt]

push %ebx
push %esi
push %edi
push %ebp

jmp $0x18, $.bits16

.code16
.bits16:
mov $0x20, %ax
mov %ax, %ds
mov %ax, %es
mov %ax, %fs
mov %ax, %gs
mov %ax, %ss
mov %cr0, %eax
and $0xfe, %al
mov %eax, %cr0
jmp $0x00, $.cs_zero
.cs_zero:
xor %ax, %ax
mov %ax, %ss
mov %esp, %ss:(.esp)
mov %ss:(.in_registers), %esp
pop %gs
pop %fs
pop %es
pop %ds
popfd
pop %ebp
pop %edi
pop %esi
pop %edx
pop %ecx
pop %ebx
pop %eax
mov %ss:(.esp), %esp
sti
.byte 0xcd
.interrupt_number: .byte 0
cli

mov %esp, %ss:(.esp)
mov %ss:(.out_registers), %esp
lea 0x28(%esp), %esp
push %eax
push %ebx
push %ecx
push %edx
push %esi
push %ebp
pushfd
push %ds
push %es
push %fs
push %gs
mov %ss:(.esp), %esp

lgdtl %ss:(.protected_mode_gdt)
lidtl %ss:(.protected_mode_idt)

mov %cr0, %eax
or $0x1, %al
mov %eax, %cr0
jmp $0x8, $.bits32

err:
cli
hlt

.bits32:
.code32
mov $0x10, %eax
mov %eax, %ds
mov %eax, %es
mov %eax, %fs
mov %eax, %gs
mov %eax, %ss

pop %ebp
pop %edi
pop %esi
pop %ebx


ret

.align 0x10
.esp: .long 0
.out_registers: .long 0
.in_registers: .long 0
.protected_mode_gdt: .quad 0
.protected_mode_idt: .quad 0
.real_mode_idt: 
    .word 0x3ff
    .long 0
