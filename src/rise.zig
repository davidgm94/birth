const common = @import("common");
comptime {
    //@compileLog("wtf");
    if (common.os != .freestanding) @compileError("Kernel file included in not the OS");
}

const privileged = @import("privileged");

pub const DeviceManager = @import("kernel/device_manager.zig");
pub const Disk = @import("kernel/disk.zig");
pub const Drivers = @import("kernel/drivers.zig");
pub const ELF = @import("kernel/elf.zig");
pub const Executable = @import("kernel/executable.zig");
pub const Filesystem = @import("kernel/filesystem.zig");
pub const Graphics = @import("kernel/graphics.zig");
pub const Heap = privileged.Heap;
pub const Memory = @import("kernel/memory.zig");
pub const Message = common.Message;
pub const MessageQueue = @import("kernel/message_queue.zig");
pub const PhysicalAddress = privileged.PhysicalAddress;
pub const PhysicalAddressSpace = privileged.PhysicalAddressSpace;
pub const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
pub const Process = @import("kernel/process.zig");
pub const Scheduler = @import("kernel/scheduler.zig");
pub const Spinlock = @import("kernel/spinlock.zig");
pub const Syscall = @import("kernel/syscall.zig");
pub const Thread = @import("kernel/thread.zig");
pub const Timer = @import("kernel/timer.zig");
pub const Window = @import("kernel/window.zig");
pub const VirtualAddress = privileged.VirtualAddress;
pub const VirtualAddressSpace = privileged.VirtualAddressSpace;
pub const VirtualMemoryRegion = privileged.VirtualMemoryRegion;

pub const FileInMemory = struct {
    address: VirtualAddress,
    size: u64,
};
