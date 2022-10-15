const common = @import("common");
const log = common.log.scoped(.Kernel);

const RNU = @import("RNU");
const DeviceManager = RNU.DeviceManager;
const FileInMemory = RNU.FileInMemory;
const Framebuffer = Graphics.Framebuffer;
const Graphics = RNU.Graphics;
const Memory = RNU.Memory;
const PhysicalAddressSpace = RNU.PhysicalAddressSpace;
const PhysicalMemoryRegion = RNU.PhysicalMemoryRegion;
const Process = RNU.Process;
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

//pub var scheduler = Scheduler{
//.lock = Spinlock{},
//.all_threads = Thread.List{},
//.active_threads = Thread.List{},
//.paused_threads = Thread.List{},
//};

pub var physical_address_space = PhysicalAddressSpace{};
pub var virtual_address_space: VirtualAddressSpace = undefined;
var bootstrap_regions: [10000]PhysicalMemoryRegion = undefined;
var bootstrap_region_count: u64 = 0;

pub fn get_bootstrap_regions() []PhysicalMemoryRegion {
    return bootstrap_regions[0..bootstrap_region_count];
}
pub fn add_bootstrap_region(physical_memory_region: PhysicalMemoryRegion) void {
    bootstrap_regions[bootstrap_region_count] = physical_memory_region;
    bootstrap_region_count += 1;
}
//pub var process: *Process = undefined;
//pub var desktop_process: *Process = undefined;

//pub var memory: Memory = .{};
//pub var memory_initialized = false;

//pub var sections_in_memory: []VirtualMemoryRegion = &.{};
//pub var file = FileInMemory{
//.address = VirtualAddress.invalid(),
//.size = 0,
//};

//pub var bootloader_framebuffer: Framebuffer = undefined;
//pub var bootloader_virtual_address_space: *VirtualAddressSpace = undefined;
//pub var higher_half_direct_map = VirtualAddress.invalid();
//pub var device_manager = DeviceManager{};
//pub var drivers_ready: bool = false;

//pub var window_manager = Window.Manager{};

pub const config = struct {
    safe_slow: bool = true,
}{};

pub fn get_boundaries() Range {
    const start = @extern(*u8, .{ .name = "kernel_start" });
    const end = @extern(*u8, .{ .name = "kernel_end" });

    return Range{
        .start = @ptrToInt(start),
        .end = @ptrToInt(end),
    };
}

//pub const main = @import("kernel/main.zig").main;

pub const higher_half = 0xffff_8000_0000_0000;

pub const Range = struct {
    start: u64,
    end: u64,

    pub fn get_size(range: Range) u64 {
        return range.end - range.start;
    }
};

pub fn get_section_boundaries(comptime section_name: []const u8) Range {
    const section_start = @extern(*u8, .{ .name = section_name ++ "_section_start", .linkage = .Weak });
    const section_end = @extern(*u8, .{ .name = section_name ++ "_section_end", .linkage = .Weak });
    return Range{
        .start = @ptrToInt(section_start),
        .end = @ptrToInt(section_end),
    };
}
