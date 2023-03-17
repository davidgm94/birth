PHDRS {
    none   PT_NULL FLAGS(0);
    text   PT_LOAD FLAGS((1 << 2) | (1 << 0) /* Readable | Executable */);
    rodata PT_LOAD FLAGS((1 << 2)            /* Readable */);
    data   PT_LOAD FLAGS((1 << 2) | (1 << 1) /* Readable | Writeable  */);
}

SECTIONS {
    . = 0xFFFFFFFF80000000;
    PROVIDE(cpu_driver_start = .);


    PROVIDE(text_section_start = .);
    .text . : {
        *(.text*)
  }:text

  . = ALIGN(4K);
  PROVIDE(text_section_end = .);

  PROVIDE(rodata_section_start = .);
  .rodata . : {
      *(.rodata*)
  }:rodata

  . = ALIGN(4K);
  PROVIDE(rodata_section_end = .);

  PROVIDE(data_section_start = .);
  .data . : {
      *(.data*)
          *(.bss*)
          *(.got*)
  }:data

  . = ALIGN(4K);
  PROVIDE(data_section_end = .);
  PROVIDE(cpu_driver_end = .);
}
