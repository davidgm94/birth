const common = @import("common");

const privileged = @import("privileged");
const UEFI = privileged.UEFI;

const arch = @import("arch");
const CPU = arch.CPU;

export fn kernel_entry_point(bootloader_info: *UEFI.BootloaderInformation) noreturn {
    _ = bootloader_info;
    CPU.stop();
}

pub fn log(comptime level: common.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    //if (!rework) {
    //arch.writer_lock.acquire();
    //defer arch.writer_lock.release();

    //const current_thread = TLS.get_current();

    //arch.writer.writeAll("[Kernel] ") catch unreachable;
    //if (current_thread.cpu) |current_cpu| {
    //arch.writer.print("[Core #{}] ", .{current_cpu.id}) catch unreachable;
    //} else {
    //arch.writer.writeAll("[WARNING: unknown core] ") catch unreachable;
    //}
    //arch.writer.print("[Process #{}] [Thread #{}] ", .{ current_thread.process.id, current_thread.id }) catch unreachable;
    //}

    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
    arch.writer.writeAll(prefix) catch unreachable;

    arch.writer.print(format, args) catch unreachable;
    arch.writer.writeByte('\n') catch unreachable;
}
