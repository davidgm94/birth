# Rise: an attempt to write a better operating system

![Build status](https://img.shields.io/github/actions/workflow/status/davidgm94/rise/lightning.yml?branch=main)

An experiment of an operating system for modern 64-bit architectures which focuses on building robust, fast and usable system software and learning how to do it along the way.

The current plan is to explore the idea of the multikernel exposed in the Barrelfish and Arrakis papers (very roughly simplified, an exokernel per core). Hopefully this academic model proves worthy, resulting in a big improvement in multiple aspects. If not, a hybrid kernel model with high-performance async syscalls will be used.

The operating system design for developers aims at fast iteration times, so there are no external dependencies aside from the execution environment and the compiler.

Currently only the Limine bootloader and a custom one are supported. Both only support BIOS and UEFI for the x86_64 architecture and both implement SMP trampoline, modules, memory map and framebuffer, among other features.

The disk image creation is currently raw (not ISO format) made by a handmade written-in-Zig FAT32 driver which needs severe improvements and bug fixing, but it does the job for now.

For each run, Github CI currently compiles all build and test artifacts and tests all the guest (only x86_64 for now) and host executables. Guest testing is done through QEMU TCG.

## High-level design goals

- Multikernel model, which would grant more safety and speed.
- Try to supress interpreted/JIT language uses in every field as much as possible, preferring compiled type-safe native languages instead and then favoring speed, robustness and safety.
- Make everything go reasonably fast (as fast as possible).
- Usable desktop, for both basic and developer purposes.
- Sandboxed execution of programs by default.
- New library and executable format for modern times, which aims at performance and scalability and admits both static and dynamic linking, preferring static.
- Prefer typed commmunication as opposed to strings, for example in program arguments and configuration files.
- Clean up shells, move away from current ones as much as possible: make it type-safe and compiled, commands are function calls from libraries instead of executables, etc.
- Promote open-source driver code (especially for GPUs, since these drivers being close-source is hurting the computing space) and simplified drivers through ISA/DMA.
- (far away in the future) Think of a way to substitute browser's Javascript for native compiled code.

## External dependencies to compile and run the code (executables your machine should have in the PATH environment variable)

* The Zig compiler (master) - This is required to compile and run the code. Apart from the operating system being written in Zig, Zig is used as a build system, so no platform-specific scripting language is needed. The easiest way to get it is to download the master binary at the website.
* QEMU - to load and execute the operating system in a virtual environment
* GDB - only for debugging

## Internal dependencies

* STB TTF

## Build and run instructions

- To build for the default target options (located in config/default.json): `zig build`
- To build and run for the default target options: `zig build run`
- To build and debug for the default target options: `zig build debug`
- To build and test for the default target options: `zig build test`
- To build and debug the tests for the default target options: `zig build test_debug`
- To build all host and guest normal artifacts: `zig build all`
- To build all host and guest test artifacts: `zig build all_tests`
- To build and run all host and guest tests: `zig build test_all`
- To run any other specialized step, please consult the steps listed in `zig build --help`

## Target architectures:

- [x] x86_64
- [ ] RISC-V 64
- [ ] aarch64

Currently only x86_64 is supported, although aarch64 and RISC-V 64 are planned for implementation.

## Target execution environments

- [x] Real hardware. BIG DISCLAIMER: Support on real hardware is really primitive as it has been implemented recently. Only the UEFI boot protocol is tested and should only be tried/tested if you know what you are doing. Moreover, since currently there is no CI for real hardware, due to the diversity of the x86-64 platform and the lack of testing, real hardware might not work as emulated ones do.

### Emulators/Hypervisors

#### QEMU
  - [x] KVM
  - [ ] XEN
  - [ ] HAX
  - [ ] HVF
  - [ ] NVMM
  - [ ] WHPX
  - [x] TCG

##### Degree of QEMU emulation supported right now:

- Linux

* [x] Run
* [x] Debug

- Windows

* [x] Run
* [ ] Debug

- MacOS

* [x] Run
* [x] Debug

#### Other execution environments

- [ ] Bochs
- [ ] VMWare
- [ ] VirtualBox

## Next tasks to be done

### General

* Implement the CPU driver according to the `multikernel` model.

## Inspirations and acknowledgements

- Linux kernel: https://kernel.org
- Barrelfish and Arrakis:
* https://barrelfish.org/
* https://arrakis.cs.washington.edu/
- Essence: https://gitlab.com/nakst/essence/
- Limine bootloader: https://github.com/limine-bootloader/limine
- Florence: https://github.com/FlorenceOS/Florence
- Managarm: https://github.com/managarm/managarm
- Jonathan Blow ideas on how an operating system should be:
* https://youtu.be/k0uE_chSnV8
* https://youtu.be/xXSIs4aTqhI
- Casey Muratori's lecture: https://youtu.be/kZRE7HIO3vk
- Zig Discord channel: https://discord.gg/gxsFFjE
- OSDev Discord channel: https://discord.gg/RnCtsqD
