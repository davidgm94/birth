# Rise

![Build status](https://img.shields.io/github/actions/workflow/status/davidgm94/rise/lightning.yml?branch=main)

An experiment of kernel for 64-bit systems which focuses on learning how to build a better operating system.

## Target architectures:

- [x] x86_64
- [ ] RISC-V 64
- [ ] aarch64

In the past there was a RISC-V implementation, but it was abandoned and later deleted in favor of the progress of the operating system per se. Once the operating system is mature enough, ports will be made to the rest of the target architectures.

BIG DISCLAIMER: Running on real hardware is not supported as of now.

## Degree of emulation supported right now:

- Linux

* [x] Run
* [x] Debug

- Windows

* [x] Run
* [ ] Debug

- MacOS

* [x] Run
* [x] Debug

## External dependencies to compile and run the code (executables your machine should have in the PATH variable)
* The Zig compiler - This is required to compile and run the code. Apart from the kernel being written in Zig, Zig is used as a build system, so no platform-specific scripting language is needed.
* QEMU - to load and execute the kernel in a virtual environment
* GDB (only for debugging)

## Internal dependencies
* STB TTF

## Next taks to be done

### General
* Improve the virtual memory manager: keep track of which virtual memory ranges are allocated
* Write free functions for the kernel physical, virtual and heap allocators
* Polish AHCI driver
* Improve memory mapping and permissions
* Implement basic syscalls
* Implement a graphics driver
* Make drivers work in userspace
* Make the kernel PIE (Position-Independent Executable)

## Boot process


### x86_64

BIOS: MBR -> ELF32 loader (loads multiple files)
                    |
                    v
(common): kernel initialization --(schedules)--> user space initializer
                ^
                |
UEFI: UEFI -> kernel 
