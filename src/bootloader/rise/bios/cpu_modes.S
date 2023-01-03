idt_protected_mode:
    .word 0x0
    .long 0x0

.macro go_real_mode
    sidt (idt_protected_mode)
    ljmpw $0x18, $.entry_16

    .code16
    .idt_real_mode:
        .word 0x3ff
        .long 0x0

    .entry_16:
        mov %cr0, %eax
        and $0xfe, %al
        mov %eax, %cr0

        jmpw $0x0,$.real_mode_entry

    .real_mode_entry:
        mov $0, %ax
        mov %ax, %ds
        mov %ax, %es
        mov %ax, %ss

        lidt (.idt_real_mode)
        sti
.endm

.macro go_protected_mode
    cli
    mov %cr0, %eax
    or $0x1, %al
    mov %eax, %cr0

    jmpl $0x8, $.protected_mode

    .protected_mode:
        .code32
        mov $0x10, %ax
        mov %ax, %ds
        mov %ax, %es
        mov %ax, %ss

        lidt (idt_protected_mode)
.endm
