SECTIONS {
  . = 0xFFFFFFFF80000000;
  kernel_start = .;

  . = ALIGN(64K);

  .text . : {
    *(.text*)
  }:text
  
  . = ALIGN(64K);

  .rodata . : {
    *(.rodata*)
  }:rodata

  . = ALIGN(64K);

  .data . : {
    *(.data*)
  }:data

  . = ALIGN(64K);

  .bss . : {
    *(.bss*)
  }
  
  . = ALIGN(64K);
}
