.section .text.entry

// Declare _start used in linker.ld script

.global _start

.set hart_stack_size, 0x8000

// a0: current HART ID
// a1: pointer to flattened device tree
_start:
    // Set up the stack and the frame pointers
    la sp, stack_top
    li t0, hart_stack_size
    mul t0, t0, a0
    sub sp, sp, t0
    mv fp, sp

    // Setup the global pointer
    .option push
    .option norelax
    lla gp, __global_pointer$
    .option pop

    // Architecture-specific initialization
    call riscv_start
