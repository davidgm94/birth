const lib = @import("lib");
const assert = lib.assert;
const log = lib.log;

const privileged = @import("privileged");
const stopCPU = privileged.arch.stopCPU;

const cpu = @import("cpu");

var lock: lib.Spinlock = .released;

pub const std_options = struct {
    pub fn logFn(comptime level: lib.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        lock.acquire();
        cpu.writer.writeAll("[CPU DRIVER] ") catch unreachable;
        cpu.writer.writeByte('[') catch unreachable;
        cpu.writer.writeAll(@tagName(scope)) catch unreachable;
        cpu.writer.writeAll("] ") catch unreachable;
        cpu.writer.writeByte('[') catch unreachable;
        cpu.writer.writeAll(@tagName(level)) catch unreachable;
        cpu.writer.writeAll("] ") catch unreachable;
        lib.format(cpu.writer, format, args) catch unreachable;
        cpu.writer.writeByte('\n') catch unreachable;

        lock.release();
    }

    pub const log_level = lib.log.Level.debug;
};

pub fn panic(message: []const u8, _: ?*lib.StackTrace, _: ?usize) noreturn {
    @call(.always_inline, cpu.panic, .{ "{s}", .{message} });
}

comptime {
    @export(cpu.arch.entryPoint, .{ .name = "_start", .linkage = .Strong });
}
