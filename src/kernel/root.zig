const std = @import("../common/std.zig");
const arch = @import("arch.zig");

pub fn log(comptime level: std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
    const current_thread = arch.get_current_thread();
    const current_cpu = current_thread.cpu orelse while (true) {};
    const processor_id = current_cpu.id;
    arch.default_io.lock.acquire();
    defer arch.default_io.lock.release();
    arch.default_io.writer.print("[Kernel] [Core #{}] [Thread #{}] ", .{ processor_id, current_thread.id }) catch unreachable;
    arch.default_io.writer.writeAll(prefix) catch unreachable;
    arch.default_io.writer.print(format, args) catch unreachable;
    arch.default_io.writer.writeByte('\n') catch unreachable;
}

//var panicking: usize = 0;
pub fn panic(message: []const u8, _: ?*std.StackTrace) noreturn {
    std.log.err("Panic happened: {s}", .{message});
    while (true) {}
}
