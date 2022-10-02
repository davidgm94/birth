const common = @import("common");
const log = common.log.scoped(.Kernel);

const RNU = @import("RNU");
const DeviceManager = RNU.DeviceManager;
const FileInMemory = RNU.FileInMemory;
const Framebuffer = Graphics.Framebuffer;
const Graphics = RNU.Graphics;
const PhysicalAddressSpace = RNU.PhysicalAddressSpace;
const Scheduler = RNU.Scheduler;
const Spinlock = RNU.Spinlock;
const Thread = RNU.Thread;
const Timer = RNU.Timer;
const VirtualAddress = RNU.VirtualAddress;
const VirtualAddressSpace = RNU.VirtualAddressSpace;
const VirtualMemoryRegion = RNU.VirtualMemoryRegion;
const Window = RNU.Window;

const arch = @import("arch");
const Context = arch.Context;
const CPU = arch.CPU;
const TLS = arch.TLS;

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
pub var bootstrap_allocator = common.FixedBufferAllocator.init(&bootstrap_memory);

pub var higher_half_direct_map = VirtualAddress.invalid();

pub var device_manager = DeviceManager{};
pub var drivers_ready: bool = false;

pub const BootstrapContext = struct {
    cpu: CPU,
    thread: Thread,
    context: Context,
};
pub var bootstrap_context: BootstrapContext = undefined;

pub var window_manager = Window.Manager{};

pub const config = struct {
    safe_slow: bool = false,
}{};

const start = @extern(*u8, .{ .name = "kernel_start" });
const end = @extern(*u8, .{ .name = "kernel_end" });

pub const main = @import("kernel/main.zig").main;
