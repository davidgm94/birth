pub const ExecutableIdentity = enum {
    kernel,
    kernel_module,
    user,
    build,
};

comptime {
    if (@import("builtin").os.tag != .freestanding) @compileError("This file is not supposed to be included in the build.zig");
}

//pub const arch = @import("common/arch.zig");
//pub const VirtualAddress = @import("common/virtual_address.zig");
//pub const PhysicalAddress = @import("common/physical_address.zig");
//pub const VirtualMemoryRegion = @import("common/virtual_memory_region.zig");
//pub const PhysicalMemoryRegion = @import("common/physical_memory_region.zig");
//pub const PhysicalAddressSpace = @import("common/physical_address_space.zig");
//pub const VirtualAddressSpace = @import("common/virtual_address_space.zig");
//pub const Thread = @import("common/thread.zig");
//pub const Scheduler = @import("common/scheduler.zig");
//pub const Syscall = @import("common/syscall.zig");
//pub const User = @import("common/user.zig");
//pub const List = @import("common/list.zig");
//pub const StableBuffer = @import("common/stable_buffer.zig");

//pub const QEMU = @import("common/qemu.zig");
//pub const ELF = @import("common/elf.zig");
//pub const RNUFS = @import("common/rnufs.zig");
//pub const PSF1 = @import("common/psf1.zig");
//pub const Heap = @import("common/heap.zig");

