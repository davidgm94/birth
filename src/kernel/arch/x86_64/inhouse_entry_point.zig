const common = @import("common");
const logger = common.log.scoped(.EntryPoint);

const privileged = @import("privileged");
const UEFI = privileged.UEFI;

const arch = @import("arch");
const CPU = arch.CPU;

export fn kernel_entry_point(bootloader_info: *UEFI.BootloaderInformation) noreturn {
    logger.debug("Hello kernel", .{});
    logger.debug("Info: {}", .{bootloader_info});
    CPU.stop();
}

pub fn log(comptime level: common.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
    writer.writeAll(prefix) catch unreachable;

    writer.print(format, args) catch unreachable;
    writer.writeByte('\n') catch unreachable;
}

const Writer = common.Writer(void, UEFI.Error, e9_write);
const writer = Writer{ .context = {} };
fn e9_write(_: void, bytes: []const u8) UEFI.Error!usize {
    const bytes_left = asm volatile (
        \\cld
        \\rep outsb
        : [ret] "={rcx}" (-> usize),
        : [dest] "{dx}" (0xe9),
          [src] "{rsi}" (bytes.ptr),
          [len] "{rcx}" (bytes.len),
    );
    return bytes.len - bytes_left;
}
