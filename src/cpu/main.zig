const lib = @import("lib");
const assert = lib.assert;
const log = lib.log;

const bootloader = @import("bootloader");
const limine = bootloader.limine;

const privileged = @import("privileged");
const stopCPU = privileged.arch.stopCPU;

const cpu = @import("cpu");

var lock: cpu.arch.Spinlock = .released;

pub const std_options = struct {
    pub fn logFn(comptime level: lib.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        _ = level;
        lock.acquire();
        cpu.writer.writeAll("[CPU DRIVER] ") catch unreachable;
        cpu.writer.writeByte('[') catch unreachable;
        cpu.writer.writeAll(@tagName(scope)) catch unreachable;
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
    switch (lib.cpu.arch) {
        .x86_64, .aarch64 => @export(limine.entryPoint, .{ .name = "limineEntryPoint", .linkage = .Strong }),
        else => {},
    }
}
pub extern fn entryPoint() callconv(.Naked) noreturn;
comptime {
    @export(cpu.arch.entryPoint, .{ .name = "entryPoint", .linkage = .Strong });
}
