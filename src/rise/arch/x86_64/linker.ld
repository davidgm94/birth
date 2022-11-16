SECTIONS {
  . = 0xFFFFFFFF80000000;
  kernel_start = .;

  . = ALIGN(4K);

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
  kernel_end = .;
}
