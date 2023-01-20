const lib = @import("lib");
const log = lib.log;
const privileged = @import("privileged");
const bootloader = @import("bootloader");

const writer = privileged.E9Writer{ .context = {} };

export fn entry_point() callconv(.Naked) noreturn {
    asm volatile(
        \\jmp *%[main_function]
    :
    : [main_function] "r" (main)
    );

    while (true) {}
}

export fn main(bootloader_information: *bootloader.Information) noreturn {
    writer.writeAll("Stage 2\n") catch unreachable;
    const ptr = @ptrToInt(bootloader_information);
    log.debug("Bootloader Information: 0x{x}", .{ptr});
    while (true) {
    }
}

pub const std_options = struct {
    pub fn logFn(comptime level: lib.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
        const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
        const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
        writer.writeAll(prefix) catch unreachable;

        writer.print(format, args) catch unreachable;
        writer.writeByte('\n') catch unreachable;
    }
    pub const log_level = lib.log.Level.debug;
};
