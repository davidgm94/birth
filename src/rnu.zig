const common = @import("common");
comptime {
    if (common.os != .freestanding) @compileError("Kernel file included in not the OS");
}
const crash = @import("kernel/crash.zig");
pub const panic = crash.panic;
pub const panic_extended = crash.panic_extended;
pub const TODO = crash.TODO;

pub const DeviceManager = @import("kernel/device_manager.zig");
pub const Disk = @import("kernel/disk.zig");
pub const Drivers = @import("kernel/drivers.zig");
pub const ELF = @import("kernel/elf.zig");
pub const Executable = @import("kernel/executable.zig");
pub const Filesystem = @import("kernel/filesystem.zig");
pub const Graphics = @import("kernel/graphics.zig");
pub const Heap = @import("kernel/heap.zig");
pub const Memory = @import("kernel/memory.zig");
pub const Message = common.Message;
pub const MessageQueue = @import("kernel/message_queue.zig");
pub const PhysicalAddress = @import("kernel/physical_address.zig");
pub const PhysicalAddressSpace = @import("kernel/physical_address_space.zig");
pub const PhysicalMemoryRegion = @import("kernel/physical_memory_region.zig");
pub const Process = @import("kernel/process.zig");
pub const Scheduler = @import("kernel/scheduler.zig");
pub const Spinlock = @import("kernel/spinlock.zig");
pub const Syscall = @import("kernel/syscall.zig");
pub const Thread = @import("kernel/thread.zig");
pub const Timer = @import("kernel/timer.zig");
pub const VirtualAddress = @import("kernel/virtual_address.zig");
pub const VirtualAddressSpace = @import("kernel/virtual_address_space.zig");
pub const VirtualMemoryRegion = @import("kernel/virtual_memory_region.zig");
pub const Window = @import("kernel/window.zig");

pub const FileInMemory = struct {
    address: VirtualAddress,
    size: u64,
};

pub const PrivilegeLevel = enum(u1) {
    kernel = 0,
    user = 1,
};
