.section .smp_trampoline
.align 0x1000

.global smp_trampoline
.global smp_trampoline_arg_start
.global smp_trampoline_arg_end
.global smp_gdt_descriptor
.global smp_core_booted
.global smp_trampoline_end

.code16
smp_trampoline:
cli
cld

mov %cs, %ebx
shl $0x4, %ebx

lidtl %cs:(invalid_idt - smp_trampoline)
lgdtl %cs:(smp_gdt_descriptor - smp_trampoline)
leal (protected_mode - smp_trampoline)(%ebx), %eax
movl %eax, %cs:(far_jump_offset - smp_trampoline)
movl $0x11, %eax
movl %eax, %cr0
mov %cs:(gdt32_ds - smp_trampoline), %eax
ljmpl *%cs:(far_jump - smp_trampoline)

far_jump:
far_jump_offset: .long 0
gdt32_cs: .long 0x18
gdt32_ds: .long 0x20

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
leal (temporal_stack_top - smp_trampoline)(%ebx), %esp

// Long mode activation

// In CR4
mov %cr4, %eax
bts $0x5, %eax
mov %eax, %cr4

// In EFER:
mov $0xc0000080, %ecx
mov $0x900, %eax
xor %edx, %edx
wrmsr

// Setup CR3
mov (arg_cr3 - smp_trampoline)(%ebx), %eax
mov %eax, %cr3

mov %cr0, %eax
bts $31, %eax
mov %eax, %cr0

leal (bits64 - smp_trampoline)(%ebx), %eax
push $0x28
push %eax
lretl

.code64
bits64:
mov $0x30, %rax
mov %rax, %ds
mov %rax, %es
mov %rax, %fs
mov %rax, %gs
mov %rax, %ss

mov %ebx, %ebx

// Enable NXE
mov $0xc0000080, %ecx
rdmsr
bts $11, %eax
wrmsr

// Enable write protect
mov %cr0, %rax
bts $16, %rax
mov %rax, %cr0

// TODO: before park
mov $1, %al
lock xchgb (smp_core_booted - smp_trampoline)(%rbx), %al
xor %rax, %rax
cli
hlt

.align 16
temporal_stack:
.fill 128, 1, 0
temporal_stack_top:

invalid_idt:
.quad 0
.quad 0

.align 16
smp_trampoline_arg_start:
arg_hhdm:
.quad 0
arg_cr3:
.long 0
reserved: .word 0
smp_gdt_descriptor:
.limit: .word 0
.address: .quad 0
smp_gdt:
smp_gdt_null: .quad 0
smp_gdt_code_16: .quad 0
smp_gdt_data_16: .quad 0
smp_gdt_code_32: .quad 0
smp_gdt_data_32: .quad 0
smp_gdt_code_64: .quad 0
smp_gdt_data_64: .quad 0
smp_trampoline_arg_end:

smp_core_booted: .byte 0

smp_trampoline_end:
