const common = @import("common.zig");

const DeviceManager = @import("device_manager.zig");
const FileInMemory = common.FileInMemory;
const Framebuffer = common.Framebuffer;
const Scheduler = @import("scheduler.zig");
const Spinlock = @import("spinlock.zig");
const Thread = @import("thread.zig");
const PhysicalAddressSpace = @import("physical_address_space.zig");
const VirtualAddress = @import("virtual_address.zig");
const VirtualAddressSpace = @import("virtual_address_space.zig");
const VirtualMemoryRegion = @import("virtual_memory_region.zig");

pub var scheduler = Scheduler{
    .lock = Spinlock{},
    .thread_buffer = Thread.Buffer{},
    .all_threads = Thread.List{},
    .active_threads = Thread.List{},
    .paused_threads = Thread.List{},
    .cpus = &.{},
    .current_threads = &.{},
    .initialized_ap_cpu_count = 0,
};

pub var physical_address_space = PhysicalAddressSpace{};

pub var virtual_address_space = VirtualAddressSpace{
    .arch = .{},
    .privilege_level = .kernel,
    .heap = .{},
    .lock = .{},
    .initialized = false,
};
pub var sections_in_memory: []VirtualMemoryRegion = &.{};
pub var file = FileInMemory{
    .address = VirtualAddress.invalid(),
    .size = 0,
};

pub var bootloader_framebuffer: Framebuffer = undefined;

pub var higher_half_direct_map = VirtualAddress.invalid();

pub var device_manager = DeviceManager{};
pub var drivers_ready: bool = false;
