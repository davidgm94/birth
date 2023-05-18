PHDRS {
  none   PT_NULL FLAGS(0);
  text   PT_LOAD FLAGS((1 << 2) | (1 << 0) /* Readable | Executable */);
  rodata PT_LOAD FLAGS((1 << 2)            /* Readable */);
  data   PT_LOAD FLAGS((1 << 2) | (1 << 1) /* Readable | Writeable  */);
}

SECTIONS {
  . = 0x600000;
  . = ALIGN(4K);
  .text . : {
    *(.text*)
  }:text
  . = ALIGN(4K);
  .rodata . : {
    *(.rodata*)
  }:rodata
  . = ALIGN(4K);
  .data . : {
    *(.data*)
    *(.bss*)
  }:data
  . = ALIGN(4K);
}
