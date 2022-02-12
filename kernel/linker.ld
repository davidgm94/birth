ENTRY(_start)

PHDRS {
  none   PT_NULL FLAGS(0);
  text   PT_LOAD FLAGS((1 << 2) | (1 << 0) /* Readable | Executable */);
  rodata PT_LOAD FLAGS((1 << 2)            /* Readable */);
  data   PT_LOAD FLAGS((1 << 2) | (1 << 1) /* Readable | Writeable  */);
}

SECTIONS {
  . = 0xFFFFFFFF80100000;

  .stivale2hdr . : {
    QUAD(_start) /* Entry point */
    QUAD(__stack_high) /* Stack */
    QUAD(0) /* Flags */
    QUAD(__stivale2_tags) /* Tags */
  }:none

  . = ALIGN(64K);

  .text . : {
    *(.text*)
  }:text
  
  . = ALIGN(64K);

  .rodata . : {
    __stivale2_tags = .;

    __framebuffer_tag = .;
    QUAD(0x3ecc1bc43d0f7971) /* identifier */
    QUAD(__after_framebuffer_tag) /* next */
    SHORT(0) /* width */
    SHORT(0) /* height */
    SHORT(0) /* bpp */
    __after_framebuffer_tag = .;

    __smp_tag = .;
    QUAD(0x1ab015085f3273df) /* identifier */
    QUAD(__after_smp_tag) /* next */
    QUAD(0) /* flags */
    __after_smp_tag = .;

    __terminal_tag = .;
    QUAD(0xa85d499b1823be72) /* identifier */
    QUAD(__after_terminal_tag) /* next */
    QUAD(0) /* flags */
    __after_terminal_tag = .;

    __mtrr_tag = .;
    QUAD(0x4c7bb07731282e00) /* identifier */
    QUAD(__after_mtrr_tag) /* next */
    __after_mtrr_tag = .;

    /* Terminate linked list */
    QUAD(0xAAAAAAAAAAAAAAAA)
    QUAD(0)

    *(.rodata*)
  }:rodata
  . = ALIGN(64K);

  .data . : {
    *(.data*)
  }:data

  .bss . : {
    __stack_low = .;
    . += 64K;
    __stack_high = .;
    *(.bss*)
  }
}
