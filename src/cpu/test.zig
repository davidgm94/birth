const lib = @import("lib");
const log = lib.log.scoped(.TEST);
const privileged = @import("privileged");
const writer = privileged.writer;

test "Hello kernel" {
    lib.testing.log_level = .debug;
    log.debug("Hello kernel test", .{});
}

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
};
