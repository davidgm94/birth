const std = @import("../common/std.zig");

const common = @import("common.zig");

const arch = @import("arch/common.zig");
const DeviceManager = @import("device_manager.zig");
const FileInMemory = common.FileInMemory;
const Framebuffer = common.Framebuffer;
const Scheduler = @import("scheduler.zig");
const Spinlock = @import("spinlock.zig");
const Thread = @import("thread.zig");
const PhysicalMemoryRegion = @import("physical_memory_region.zig");
const PhysicalAddressSpace = @import("physical_address_space.zig");
const VirtualAddress = @import("virtual_address.zig");
const VirtualAddressSpace = @import("virtual_address_space.zig");
const VirtualMemoryRegion = @import("virtual_memory_region.zig");

const CPU = arch.CPU;
const Context = arch.Context;

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
};

pub var memory_initialized = false;

pub var sections_in_memory: []VirtualMemoryRegion = &.{};
pub var file = FileInMemory{
    .address = VirtualAddress.invalid(),
    .size = 0,
};

pub var bootloader_framebuffer: Framebuffer = undefined;
pub var bootstrap_virtual_address_space: *VirtualAddressSpace = undefined;
var bootstrap_memory: [0x1000 * 30]u8 = undefined;
pub var bootstrap_allocator = std.FixedBufferAllocator.init(&bootstrap_memory);

pub var higher_half_direct_map = VirtualAddress.invalid();

pub var device_manager = DeviceManager{};
pub var drivers_ready: bool = false;

pub const BootstrapContext = struct {
    cpu: CPU,
    thread: Thread,
    context: Context,
};
pub var bootstrap_context: BootstrapContext = undefined;

pub const config = struct {
    safe_slow: bool = true,
}{};
