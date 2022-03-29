const std = @import("std");
const builtin = @import("builtin");
const logger = std.log.scoped(.init);

pub const arch = @import("arch/riscv64.zig");
//pub const arch = switch (builtin.target.cpu.arch) {
//.riscv64 => @import("arch/riscv64.zig"),
//.x86_64 => @import("arch/x86_64.zig"),
//else => unreachable,
//};

pub inline fn align_forward(n: u64, alignment: u64) u64 {
    const mask: u64 = alignment - 1;
    const result = (n + mask) & ~mask;
    return result;
}

pub fn TODO(src: std.builtin.SourceLocation) noreturn {
    @setCold(true);
    panicf("To be implemented at {s}:{}:{} ({s})\n", .{ src.file, src.line, src.column, src.fn_name });
}

pub inline fn assert(src: std.builtin.SourceLocation, condition: bool) void {
    if (!condition) panicf("Assert failed at {s}:{}:{} ({s})\n", .{ src.file, src.line, src.column, src.fn_name });
}

pub inline fn string_eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
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

    //arch.Clock.enable(); // Accept timer interrupt
    logger.debug("Clock IRQ initialized with {} Hz", .{arch.HZ});

    // Done initializing interrupt
    logger.debug("Initialized IRQ.", .{});
    //arch.set_timer(1); // Set next timer to something other than 0 to activate timer
    arch.enable_interrupts();
    logger.info("IRQ enabled.", .{});

    // Parse Device Tree
    arch.get_memory_map();

    // Prepare for paging
    arch.virtual.init(); // Physical memory
    arch.virtual.kernel_vm_init(); // Build kernel pagetable

    // Enable paging
    arch.virtual.enablePaging();
    logger.info("Memory paging enabled", .{});

    arch.setup_external_interrupts();
    arch.init_devices();

    //asm volatile ("ebreak");

    logger.debug("After breakpoint", .{});

    arch.read_file_test();
    while (true) {}
    std.log.info("Shutting down", .{});
    arch.shutdown(); // No return for shutdown
}
