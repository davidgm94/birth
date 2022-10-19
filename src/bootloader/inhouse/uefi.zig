const common = @import("common");
const config = common.config;
const logger = common.log.scoped(.UEFI);
const uefi = common.std.os.uefi;
const result = uefi.Status.err;
const BootServices = uefi.tables.BootServices;
const GraphicsOutputProtocol = uefi.protocols.GraphicsOutputProtocol;
const SimpleTextOutputProtocol = uefi.protocols.SimpleTextOutputProtocol;
const Status = uefi.Status;
const SystemTable = uefi.tables.SystemTable;
const EFIError = Status.EfiError;

const str16 = common.std.unicode.utf8ToUtf16LeStringLiteral;

pub fn uefi_main(system_table: *SystemTable) !noreturn {
    const out = system_table.con_out orelse return Error.missing_con_out;
    try result(out.reset(true));
    try result(out.clearScreen());
    const revision_string = switch (system_table.firmware_revision) {
        uefi.tables.SystemTable.revision_1_02 => "1.02",
        uefi.tables.SystemTable.revision_1_10 => "1.10",
        uefi.tables.SystemTable.revision_2_00 => "2.00",
        uefi.tables.SystemTable.revision_2_10 => "2.10",
        uefi.tables.SystemTable.revision_2_20 => "2.20",
        uefi.tables.SystemTable.revision_2_30 => "2.30",
        uefi.tables.SystemTable.revision_2_31 => "2.31",
        uefi.tables.SystemTable.revision_2_40 => "2.40",
        uefi.tables.SystemTable.revision_2_50 => "2.50",
        uefi.tables.SystemTable.revision_2_60 => "2.60",
        uefi.tables.SystemTable.revision_2_70 => "2.70",
        uefi.tables.SystemTable.revision_2_80 => "2.80",
        else => "Unrecognized EFI version: check that Zig UEFI standard library is up-to-date and, if not, BIOS is corrupted",
    };

    logger.debug("EFI revision: {s}", .{revision_string});

    success();
}

pub fn main() noreturn {
    uefi_main(uefi.system_table) catch |err| {
        uefi_panic("panic: {}", .{err});
    };
}

fn locate_protocol(boot_services: *BootServices, comptime Protocol: type) EFIError!*Protocol {
    var pointer_buffer: ?*anyopaque = null;
    try result(boot_services.locateProtocol(&Protocol.guid, null, &pointer_buffer));
    return @ptrCast(*Protocol, @alignCast(@alignOf(Protocol), pointer_buffer));
}

fn success() noreturn {
    logger.debug("Reached to the end of the current implementation successfully!", .{});
    halt();
}

inline fn halt() noreturn {
    asm volatile (
        \\cli
        \\hlt
    );
    unreachable;
}

pub const log_level = common.std.log.Level.debug;

pub fn log(comptime level: common.std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
    switch (common.cpu.arch) {
        .x86_64 => {
            if (config.real_hardware) {
                var buffer: [4096]u8 = undefined;
                const formatted_buffer = common.std.fmt.bufPrint(buffer[0..], prefix ++ format ++ "\n", args) catch unreachable;

                for (formatted_buffer) |c| {
                    const fake_c = [2]u16{ c, 0 };
                    _ = uefi.system_table.con_out.?.outputString(@ptrCast(*const [1:0]u16, &fake_c));
                }
            } else {
                debug_writer.print(prefix ++ format ++ "\n", args) catch unreachable;
            }
        },
        else => @compileError("Unsupported CPU architecture"),
    }
}

pub fn panic(message: []const u8, _: ?*common.std.builtin.StackTrace, _: ?usize) noreturn {
    uefi_panic("{s}", .{message});
}

pub fn uefi_panic(comptime format: []const u8, arguments: anytype) noreturn {
    common.std.log.scoped(.PANIC).err(format, arguments);
    halt();
}

const Error = error{
    missing_con_out,
    missing_boot_services,
};

const Writer = common.Writer(void, EFIError, e9_write);
const debug_writer = Writer{ .context = {} };
fn e9_write(_: void, bytes: []const u8) EFIError!usize {
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

//u8 => asm volatile ("outb %[value], %[port]"
//:
//: [value] "{al}" (value),
//[port] "N{dx}" (port),
//),
