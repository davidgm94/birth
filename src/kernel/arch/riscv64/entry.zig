export fn start(boot_hart_id: u64, fdt_address: u64) callconv(.C) noreturn {
    _ = boot_hart_id;
    _ = fdt_address;
    unreachable;
    //current_cpu = boot_hart_id;
    //register_trap_handler(@ptrToInt(trap));
    //init_logger();
    //log.debug("Hello RNU. Arch: {s}. Build mode: {s}. Boot HART id: {}. Device tree address: 0x{x}", .{ @tagName(kernel.current_arch), @tagName(common.build_mode), boot_hart_id, fdt_address });
    //device_tree.base_address = fdt_address;
    //device_tree.parse();
    //init_cpu_count();
    //Timer.init();
    //const time_start = Timer.get_timestamp();
    //Paging.init();
    //Interrupts.init(boot_hart_id);
    //local_storage[boot_hart_id].init(boot_hart_id, true);
    //const time = Timer.get_time_from_timestamp(Timer.get_timestamp() - time_start);
    //init_persistent_storage();
    //init_graphics();

    //kernel.graphics.drivers[0].draw_horizontal_line(kernel.graphics.Line{ .start = kernel.graphics.Point{ .x = 10, .y = 10 }, .end = kernel.graphics.Point{ .x = 100, .y = 10 } }, kernel.graphics.Color{ .red = 0, .green = 0, .blue = 0, .alpha = 0 });
    //kernel.graphics.drivers[0].test_draw_rect();
    //kernel.graphics.drivers[0].draw_rect(kernel.graphics.Rect{ .x = 10, .y = 10, .width = 10, .height = 10 }, kernel.graphics.Color{ .red = 0, .green = 0, .blue = 0, .alpha = 0 });
    //var i: u64 = 0;
    //while (i < 100) : (i += 1) {
    //kernel.graphics.drivers[0].draw_string(kernel.graphics.Color{ .red = 0, .green = 0, .blue = 0, .alpha = 0 }, "Hello Mariana");
    //}
    //@ptrCast(*virtio.GPU, kernel.graphics.drivers[0]).send_and_flush_framebuffer();

    //log.debug("Initialized in {} s {} us", .{ time.s, time.us });
    //spinloop();
    ////kernel.scheduler.schedule();
}
