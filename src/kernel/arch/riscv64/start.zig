const kernel = @import("../../kernel.zig");
const arch = kernel.arch;

const log = kernel.log.scoped(.init);

pub fn start(boot_hart_id: u64, fdt_address: u64) callconv(.C) noreturn {
    arch.current_cpu = boot_hart_id;
    init_logger();
    log.debug("Hello RNU. Arch: {s}. Build mode: {s}. Boot HART id: {}. Device tree address: 0x{x}", .{ @tagName(kernel.current_arch), @tagName(kernel.build_mode), boot_hart_id, fdt_address });
    arch.device_tree.base_address = fdt_address;
    arch.device_tree.parse();
    init_cpu_count();
    arch.Timer.init();
    const time_start = arch.Timer.get_timestamp();
    arch.Paging.init();
    arch.Interrupts.init(boot_hart_id);
    arch.local_storage[boot_hart_id].init(boot_hart_id, true);
    const time = arch.Timer.get_time_from_timestamp(arch.Timer.get_timestamp() - time_start);
    arch.virtio.block.init(0x10008000);
    arch.virtio.gpu.init(0x10007000);
    const file = arch.read_disk_raw(&file_buffer, 0, kernel.bytes_to_sector(file_size));
    kernel.font = kernel.PSF1.Font.parse(file);
    kernel.graphics.draw_horizontal_line(kernel.graphics.Line{ .start = kernel.graphics.Point{ .x = 10, .y = 10 }, .end = kernel.graphics.Point{ .x = 100, .y = 10 } }, kernel.graphics.Color{ .red = 0, .green = 0, .blue = 0, .alpha = 0 });
    kernel.graphics.test_draw_rect();
    //kernel.graphics.draw_rect(kernel.graphics.Rect{ .x = 10, .y = 10, .width = 10, .height = 10 }, kernel.graphics.Color{ .red = 0, .green = 0, .blue = 0, .alpha = 0 });
    //var i: u64 = 0;
    //while (i < 100) : (i += 1) {
    //kernel.graphics.draw_string(kernel.graphics.Color{ .red = 0, .green = 0, .blue = 0, .alpha = 0 }, "Hello Mariana");
    //}
    log.debug("F W: {}. F H: {}", .{ kernel.framebuffer.width, kernel.framebuffer.height });
    arch.virtio.gpu.send_and_flush_framebuffer();
    kernel.framebuffer_initialized = true;

    log.debug("Initialized in {} s {} us", .{ time.s, time.us });
    arch.spinloop();
}

fn init_logger() void {
    arch.uart.init(false);
}

fn init_cpu_count() void {
    log.debug("CPU count initialized with 1. Is it correct?", .{});
    // TODO: take from the device tree
    arch.cpu_count = 1;
}

const file_size = 5312;
var file_buffer: [kernel.align_forward(file_size, arch.sector_size)]u8 align(kernel.arch.page_size) = undefined;
