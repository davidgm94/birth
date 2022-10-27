const common = @import("common");
const logger = common.log.scoped(.EntryPoint);

const privileged = @import("privileged");
const UEFI = privileged.UEFI;

const arch = @import("arch");
const CPU = arch.CPU;
const x86_64 = arch.x86_64;
const APIC = x86_64.APIC;
const IDT = x86_64.IDT;

export fn kernel_entry_point(_: *UEFI.BootloaderInformation) noreturn {
    logger.debug("Hello kernel", .{});
    IDT.setup();
    logger.debug("Loaded IDT", .{});
    APIC.init();
    CPU.stop();
}

pub fn log(comptime level: common.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
    writer.writeAll(prefix) catch unreachable;

    writer.print(format, args) catch unreachable;
    writer.writeByte('\n') catch unreachable;
}

pub fn panic(message: []const u8, _: ?*common.StackTrace, _: ?usize) noreturn {
    asm volatile (
        \\cli
    );
    common.log.scoped(.PANIC).err("{s}", .{message});
    CPU.stop();
}

const Writer = common.Writer(void, error{}, e9_write);
const writer = Writer{ .context = {} };
fn e9_write(_: void, bytes: []const u8) error{}!usize {
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
