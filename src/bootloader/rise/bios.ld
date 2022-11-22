PHDRS {
    none   PT_NULL FLAGS(0);
    text   PT_LOAD FLAGS((1 << 2) | (1 << 0) /* Readable | Executable */);
    rodata PT_LOAD FLAGS((1 << 2)            /* Readable */);
    data   PT_LOAD FLAGS((1 << 2) | (1 << 1) /* Readable | Writeable  */);
}

SECTIONS {
    . = 0x8000;
    . = ALIGN(0x200);
    .text . : {
        *(.text*)
  }:text
    . = ALIGN(0x200);
  .rodata . : {
      *(.rodata*)
  }:rodata
    . = ALIGN(0x200);
  .data . : {
      *(.data*)
          *(.bss*)
  }:data
  . = ALIGN(0x200);
}
