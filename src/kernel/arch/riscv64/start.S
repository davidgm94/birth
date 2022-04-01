.section .text.entry

// Declare _start used in linker.ld script

.global _start

.set hart_stack_size, 0x8000

// a0: current HART ID
// a1: pointer to flattened device tree
_start:
    la sp, stack_top
    li t0, hart_stack_size
    mul t0, t0, a0
    sub sp, sp, t0
    mv fp, sp

    // TODO: initialize global pointers
    la t0, kernel_raw_interrupt_handler
    csrw stvec, t0

    // Architecture-specific routine
    call init
