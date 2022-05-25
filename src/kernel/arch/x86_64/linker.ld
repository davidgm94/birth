/* Tell the linker that we want an x86_64 ELF64 output file */
OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
 
/* We want the symbol _start to be our entry point */
ENTRY(_start)
 
/* Define the program headers we want so the bootloader gives us the right */
/* MMU permissions */
PHDRS
{
    null    PT_NULL    FLAGS(0) ;                   /* Null segment */
    text    PT_LOAD    FLAGS((1 << 0) | (1 << 2)) ; /* Execute + Read */
    rodata  PT_LOAD    FLAGS((1 << 2)) ;            /* Read only */
    data    PT_LOAD    FLAGS((1 << 1) | (1 << 2)) ; /* Write + Read */
}

SECTIONS {
  . = 0xFFFFFFFF80100000;

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
    __stack_low = .;
    . += 64K;
    __stack_high = .;
    *(.bss*)
  }
}
