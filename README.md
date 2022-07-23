# RNU - Renaissance is NOT UNIX!

An experiment of RISC-V and x86_64 kernel which focuses on learning to build a better operating system.
Currently the RISC-V architecture part has been deleted in favor of advancing with x86_64. Once the operating system is mature enough, a port will be made to this architecture (also aarch64).

## External dependencies to compile and run the code (executables your machine should have in the PATH variable)
* The Zig compiler - to compile the kernel code
* xorriso - to create the image to be loaded (only x86_64)
* QEMU - to load and execute the kernel in a virtual environment
* x86_64/riscv64 GDB (for debugging)

## Internal dependencies
* Limine, which is the current bootloader of the kernel for x86_64

## Next taks to be done

### General
* Improve the virtual memory manager: keep track of which virtual memory ranges are allocated
* Write free functions for the kernel physical, virtual and heap allocators
* Should we consider processes?
* Polish NVMe driver
* Improve memory mapping and permissions
* Implement basic syscalls
* Implement a graphics driver
* Make drivers work in userspace
* Make the kernel PIE (Position-Independent Executable)

### RISC-V
* Retake once the operating system is mature enough

### x86_64
* To consider: update to Limine protocol and forget about Stivale 2?

## Task to be done in order to update Limine
* Update at the same time the Stivale and Limine files
