const std = @import("../common/std.zig");

const kernel = @import("kernel.zig");
const TLS = @import("arch/tls.zig");

const log = std.log.scoped(.Main);

pub export fn main() callconv(.C) noreturn {
    if (kernel.scheduler.cpus.len != 1) @panic("WTF");
    kernel.device_manager.init(&kernel.virtual_address_space) catch @panic("Failed to initialize drivers");
    for (kernel.scheduler.cpus) |*cpu| {
        cpu.ready = true;
    }

    var current_thread = TLS.get_current();
    log.debug("Current thread before yielding: #{}", .{current_thread.id});
    const main_storage = kernel.device_manager.devices.filesystem.get_main_device();
    _ = kernel.scheduler.load_executable(&kernel.virtual_address_space, .user, &kernel.physical_address_space, main_storage, "minimal.elf") catch @panic("wtf");

    current_thread = TLS.get_current();
    log.debug("Current thread just before yielding: #{}", .{current_thread.id});

    asm volatile ("int $0x40");
    current_thread = TLS.get_current();
    log.debug("Current thread after yielding: #{}", .{current_thread.id});
    //device_manager.initialize_graphics(&virtual_address_space);

    while (true) {}

    //success_and_end();

}
