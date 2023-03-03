const lib = @import("lib");
const privileged = @import("privileged");
pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    privileged.arch.disableInterrupts();
    privileged.writer.writeAll("[CPU DRIVER] [PANIC] ") catch unreachable;
    privileged.writer.print(format, arguments) catch unreachable;
    privileged.writer.writeByte('\n') catch unreachable;
    privileged.arch.stopCPU();
}

pub const test_runner = @import("cpu/test_runner.zig");

pub const arch = @import("cpu/arch.zig");

pub export var stack: [0x4000]u8 align(0x1000) = undefined;
