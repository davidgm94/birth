# Simple aarch64 and x86_64 kernel in zig

Simply run either of:
```
zig build run-aarch64
zig build run-x86_64-bios
zig build run-x86_64-uefi
```
to start the kernel in qemu.

The default target
```
zig build
```
builds all kernels and images.

To flash a x86_64 universal (both bios and uefi) to a usb drive
```
zig build x86_64-universal-image
dd if=zig-cache/universal.iso of=/dev/disk/by-id/my-usb-drive bs=1048576
sync
```
