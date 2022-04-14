# RNU - Renaissance is NOT UNIX!

An experiment of RISC-V and x86_64 kernel which focuses on learning to build a better operating system.

## External dependencies to compile and run the code
* The Zig compiler - to compile the kernel code
* xorriso - to create the image to be loaded (only x86_64)
* QEMU - to load and execute the kernel in a virtual environment
* x86_64/riscv64 GDB (for debugging)

## Internal dependencies
* Limine, which is the current bootloader of the kernel for x86_64

## Tasks to be done

### RISC-V
* Write a kernel heap allocator
* Write the Virtio GPU driver
* Start implementing processes
* Memory mapping other than identity
* Memory permissions
* Userspace

### x86_64
* Catch up to the RISCV progress
* ACPI
* memory map

## Task to be done in order to update Limine
* update at the same time the stivale and limine files
