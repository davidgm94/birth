const common = @import("common");
const log = common.log.scoped(.main);

const RNU = @import("RNU");
const Timer = RNU.Timer;

const kernel = @import("kernel");

pub export fn main() callconv(.C) noreturn {
    var timer = Timer.new();
    if (kernel.scheduler.cpus.len != 1) @panic("WTF");
    kernel.device_manager.init(&kernel.virtual_address_space) catch @panic("Failed to initialize drivers");
    for (kernel.scheduler.cpus) |*cpu| {
        cpu.ready = true;
    }

    const main_storage = kernel.device_manager.devices.filesystem.get_main_device();
    _ = kernel.scheduler.load_executable(&kernel.virtual_address_space, .user, &kernel.physical_address_space, main_storage, "desktop.elf") catch @panic("wtf");

    const main_cycles = timer.end_and_get_metric();
    log.info("Main took {} cycles", .{main_cycles});
    asm volatile ("int $0x40");

    while (true) {}
}
