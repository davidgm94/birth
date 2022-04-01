OUTPUT_ARCH(riscv)
OUTPUT_FORMAT("elf64-littleriscv")

/* Entry Point */
ENTRY(_start)

/* OpenSBI transfer control to this address */
BASE_ADDRESS = 0x80200000;
HART_STACK_SIZE = 0x8000;
HART_COUNT = 64;

SECTIONS
{
    . = BASE_ADDRESS;
    PROVIDE(kernel_start = .);

    . = ALIGN(4K);
    PROVIDE(text_start = .);
    .text : {
        /* All text section off object file */
        *(.text .text.*)
    }

    . = ALIGN(4K);
    PROVIDE(rodata_start = .);
    .rodata : {
        *(.rodata .rodata.*)
    }

    . = ALIGN(4K);
    PROVIDE(data_start = .);
    .data : {
        *(.data .data.*)
    }

    . = ALIGN(4K);
    PROVIDE(sdata_start = .);
    .sdata : {
        *(.sdata .sdata.*)
    }

    . = ALIGN(4K);
    PROVIDE(bss_start = .);
    .bss : {
        *(.bss .bss.*)
    }

    . = ALIGN(4K);
    PROVIDE(stack_start = .);
    . += HART_COUNT * HART_STACK_SIZE;
    PROVIDE(stack_top = .);

    . = ALIGN(4K);
    PROVIDE(sbss_start = .);
    .sbss : {
        *(.sbss .sbss.*)
    }

    . = ALIGN(4K);
    PROVIDE(kernel_end = .);
}
