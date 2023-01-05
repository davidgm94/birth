const lib = @import("lib");
const privileged = @import("privileged");

const BIOS = privileged.BIOS;

export fn loop() noreturn {
    asm volatile (
        \\cli
        \\hlt
    );
    while (true) {}
}

var real_mode_ds: u16 = 0;

export fn _start() noreturn {
    logger.debug("Hello loader!", .{});
    BIOS.a20_enable() catch @panic("can't enable a20");
    const memory_map_entries = BIOS.e820_init() catch @panic("can't init e820");
    for (memory_map_entries) |memory_map_entry| {
        logger.debug("Entry {s}. Address: 0x{x}. Size: 0x{x}", .{ @tagName(memory_map_entry.type), memory_map_entry.base, memory_map_entry.len });
    }

    var bios_disk = BIOS.Disk{
        .disk = .{
            // TODO:
            .disk_size = 64 * 1024 * 1024,
            .sector_size = 0x200,
            .callbacks = .{
                .read = BIOS.Disk.read,
                .write = BIOS.Disk.write,
            },
            .type = .bios,
        },
    };

    const disk = &bios_disk.disk;

    _ = disk;
    logger.debug("End of bootloader", .{});
    loop();
}

pub const logger = lib.log.scoped(.Loader);
pub const log_level = lib.log.Level.debug;
pub const writer = privileged.E9Writer{ .context = {} };

pub fn log(comptime level: lib.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
    writer.print(prefix ++ format ++ "\n", args) catch unreachable;
}

pub fn panic(message: []const u8, stack_trace: ?*lib.StackTrace, ret_addr: ?usize) noreturn {
    _ = stack_trace;
    _ = ret_addr;

    lib.log.scoped(.PANIC).err("{s}", .{message});
    asm volatile (
        \\cli
        \\hlt
    );
    while (true) {}
}
