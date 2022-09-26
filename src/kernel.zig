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

pub export fn main() callconv(.C) noreturn {
    var timer = Timer.new();
    if (scheduler.cpus.len != 1) @panic("WTF");
    device_manager.init(&virtual_address_space) catch @panic("Failed to initialize drivers");
    for (scheduler.cpus) |*cpu| {
        cpu.ready = true;
    }

    var current_thread = TLS.get_current();
    log.debug("Current thread before yielding: #{}", .{current_thread.id});
    const main_storage = device_manager.devices.filesystem.get_main_device();
    _ = scheduler.load_executable(&virtual_address_space, .user, &physical_address_space, main_storage, "minimal.elf") catch @panic("wtf");

    current_thread = TLS.get_current();
    log.debug("Current thread just before yielding: #{}", .{current_thread.id});

    const main_cycles = timer.end_and_get_metric();
    log.info("Main took {} cycles", .{main_cycles});
    asm volatile ("int $0x40");
    current_thread = TLS.get_current();
    log.debug("Current thread after yielding: #{}", .{current_thread.id});

    while (true) {}
}
