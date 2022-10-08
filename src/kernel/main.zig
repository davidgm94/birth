const common = @import("common");
const assert = common.assert;
const log = common.log.scoped(.main);

const RNU = @import("RNU");
const Executable = RNU.Executable;
const panic = RNU.panic;
const Process = RNU.Process;
const Timer = RNU.Timer;

const kernel = @import("kernel");

pub export fn main() callconv(.C) noreturn {
    var timer = Timer.new();
    const cpu_count = kernel.memory.cpus.items.len;
    if (cpu_count != 1) panic("Unexpected CPU count: {}", .{cpu_count});
    kernel.device_manager.init(kernel.virtual_address_space) catch |err| panic("Failed to initialize drivers: {}", .{err});
    for (kernel.memory.cpus.items) |*cpu| {
        cpu.ready = true;
    }

    start_desktop_process() catch |err| panic("Unable to start desktop process: {}", .{err});

    const main_cycles = timer.end_and_get_metric();
    log.info("Main took {} cycles", .{main_cycles});
    asm volatile ("int $0x40");

    while (true) {}
}

fn start_desktop_process() !void {
    const main_storage = kernel.device_manager.devices.filesystem.get_main_device();
    const executable_file = try main_storage.read_file(kernel.virtual_address_space, "desktop.elf");
    const executable_format = try Executable.Format.detect(executable_file);
    const in_kernel_memory_executable = try Executable.load_into_kernel_memory(executable_file, executable_format);
    kernel.desktop_process = try Process.from_executable_in_memory(.desktop, in_kernel_memory_executable);
}
