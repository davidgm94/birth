pub const arch = @import("arch/riscv64/riscv.zig");
const std = @import("std");
const builtin = @import("builtin");
const page_size = arch.page_size;

const logger = std.log.scoped(.init);

pub fn main() noreturn {
    // TODO: panic if HZ value is unreasonable
    // No interrupt during initialization
    arch.enable_interrupts();

    arch.init_logging();

    // Boot message
    logger.debug("\n============= Booting RNU... ===============\n\n", .{});

    // Boot CPU ID

    // Initial interrupt handling
    logger.debug("Initializing IRQ...", .{});
    arch.init_interrupts(); // Interrupt Vector

    arch.Clock.enable(); // Accept timer interrupt
    logger.debug("Clock IRQ initialized with {} Hz", .{arch.HZ});

    // Done initializing interrupt
    logger.debug("Initialized IRQ.", .{});
    arch.set_timer(1); // Set next timer to something other than 0 to activate timer
    arch.enable_interrupts();
    logger.info("IRQ enabled.", .{});

    // Parse Device Tree
    arch.get_memory_map();

    // Prepare for paging
    virtual.init(); // Physical memory
    virtual.kernel_vm_init(); // Build kernel pagetable

    // Enable paging
    virtual.enablePaging();
    logger.info("Memory paging enabled", .{});

    arch.setup_external_interrupts();
    arch.init_devices();

    //asm volatile ("ebreak");

    logger.debug("After breakpoint", .{});

    while (true) {}
    std.log.info("Shutting down", .{});
    arch.shutdown(); // No return for shutdown
}

pub fn panicf(comptime format: []const u8, args: anytype) noreturn {
    @setCold(true);
    arch.disable_interrupts();

    arch.writer.writeAll("Panic: ") catch unreachable;
    arch.writer.print(format, args) catch unreachable;

    while (true) {
        std.atomic.spinLoopHint();
    }
}

pub const MemoryRegion = struct {
    address: u64,
    size: u64,
    bitset: []u8,
    allocated_page_count: u64,
};

