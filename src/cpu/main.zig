const lib = @import("lib");
const assert = lib.assert;
const log = lib.log;

const bootloader = @import("bootloader");
const limine = bootloader.limine;

const privileged = @import("privileged");
const stopCPU = privileged.arch.stopCPU;

const cpu = @import("cpu");

const writer = privileged.E9Writer{ .context = {} };

pub const panic = privileged.zigPanic;

pub const std_options = struct {
    pub fn logFn(comptime level: lib.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        _ = level;
        writer.writeAll("[CPU DRIVER] ") catch unreachable;
        writer.writeByte('[') catch unreachable;
        writer.writeAll(@tagName(scope)) catch unreachable;
        writer.writeAll("] ") catch unreachable;
        lib.format(writer, format, args) catch unreachable;
        writer.writeByte('\n') catch unreachable;
    }

    pub const log_level = lib.log.Level.debug;
};

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
