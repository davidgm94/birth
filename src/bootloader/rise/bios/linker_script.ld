PHDRS {
    none   PT_NULL FLAGS(0);
    text   PT_LOAD FLAGS((1 << 2) | (1 << 0) /* Readable | Executable */);
    rodata PT_LOAD FLAGS((1 << 2)            /* Readable */);
    data   PT_LOAD FLAGS((1 << 2) | (1 << 1) /* Readable | Writeable  */);
}

SECTIONS {
    . = 0x1000;
    loader_start = .;
    .text . : {
        *(.smp_trampoline*)
        *(.realmode*)
        *(.text*)
    }:text
    . = ALIGN(0x10);
    .rodata . : {
        *(.rodata*)
    }:rodata
    . = ALIGN(0x10);
    .data . : {
        *(.data*)
        *(.bss*)
    }:data
    . = ALIGN(0x10);
    loader_end = .;
}
