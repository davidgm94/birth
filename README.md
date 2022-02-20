Using the zig-stivale2-barebones repo to build a custom kernel

Dependencies:
* The Zig compiler - to compile the kernel code
* xorriso - to create the image to be loaded
* QEMU - to load and execute the kernel in a virtual environment
* x86_64 GDB (for debugging)

Internal dependencies are only Limine, which is the current bootloader of the kernel
