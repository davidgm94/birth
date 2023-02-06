const bootloader = @import("../../bootloader.zig");
const limine = bootloader.limine;
const lib = @import("../../lib.zig");
const assert = lib.assert;
const log = lib.log;
const privileged = @import("../../privileged.zig");
const stopCPU = privileged.arch.stopCPU;

export fn _start() noreturn {
    log.debug("Hello from Limine {s}!", .{limine_information.response.?.version});
    const hhdm = limine_hhdm.response.?.offset;
    assert(limine_stack_size.response != null);
    const stack_size = limine_stack_size.stack_size;
    const framebuffers = limine_framebuffer.response.?.framebuffers.?.*[0..limine_framebuffer.response.?.framebuffer_count];
    log.debug("Limine requests:\nHHDM: 0x{x}\nStack size: 0x{x}", .{ hhdm, stack_size });
    log.debug("Framebuffers:", .{});
    for (framebuffers) |framebuffer| {
        log.debug("{}", .{framebuffer});
    }
    log.debug("CPU count: {}", .{limine_smp.response.?.cpu_count});
    log.debug("Memory map entry count: {}", .{limine_memory_map.response.?.entry_count});

    stopCPU();
}

export var limine_information = limine.BootloaderInfo.Request{ .revision = 0 };
export var limine_stack_size = limine.StackSize.Request{ .revision = 0, .stack_size = 0x4000 };
export var limine_hhdm = limine.HHDM.Request{ .revision = 0 };
export var limine_framebuffer = limine.Framebuffer.Request{ .revision = 0 };
export var limine_smp = limine.SMPInfoRequest{ .revision = 0, .flags = .{ .x2apic = false } };
export var limine_memory_map = limine.MemoryMap.Request{ .revision = 0 };

pub const std_options = struct {
    pub const log_level = lib.log.Level.debug;
    pub fn logFn(comptime level: lib.std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        _ = scope;
        _ = level;
        lib.format(privileged.writer, format, args) catch unreachable;
        privileged.writer.writeByte('\n') catch unreachable;
    }
};
