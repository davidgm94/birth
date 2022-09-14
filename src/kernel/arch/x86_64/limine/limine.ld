SECTIONS {
  . = 0xFFFFFFFF80000000;
  kernel_start = .;

  . = ALIGN(64K);

  text_section_start = .;
  .text . : {
    *(.text*)
  }:text
  
  . = ALIGN(64K);
  text_section_end = .;

  rodata_section_start = .;
  .rodata . : {
    *(.rodata*)
  }:rodata

  . = ALIGN(64K);
  rodata_section_end = .;

  data_section_start = .;
  .data . : {
    *(.data*)
  }:data

  . = ALIGN(64K);

  .bss . : {
    *(.bss*)
  }
  
  . = ALIGN(64K);
  data_section_end = .;
}
