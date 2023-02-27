PHDRS {
    none   PT_NULL FLAGS(0);
    text   PT_LOAD FLAGS((1 << 2) | (1 << 0) /* Readable | Executable */);
    rodata PT_LOAD FLAGS((1 << 2)            /* Readable */);
    data   PT_LOAD FLAGS((1 << 2) | (1 << 1) /* Readable | Writeable  */);
}

SECTIONS {
  . = 0xFFFFFFFF80000000;
  cpu_driver_start = .;


  text_section_start = .;
  .text . : {
    *(.text*)
  }:text
  
  . = ALIGN(4K);
  text_section_end = .;

  rodata_section_start = .;
  .rodata . : {
    *(.rodata*)
  }:rodata

  . = ALIGN(4K);
  rodata_section_end = .;

  data_section_start = .;
  .data . : {
    *(.data*)
    *(.bss*)
  }:data

  . = ALIGN(4K);
  data_section_end = .;
  cpu_driver_end = .;
}
