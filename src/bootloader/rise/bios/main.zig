const lib = @import("lib");
const BIOS = @import("bios.zig");
export fn loop() noreturn {
    asm volatile (
        \\cli
        \\hlt
    );
    while (true) {}
}

var real_mode_ds: u16 = 0;

export fn _start() noreturn {
    BIOS.a20_enable() catch @panic("can't enable a20");
    logger.debug("Hello loader!", .{});

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
    const result = disk.callbacks.read(disk, 0x20, 0x800) catch @panic("Wtf");
    logger.debug("result[0] = 0x{x}", .{result[0]});
    loop();
}

const Writer = lib.Writer(void, error{}, e9_write);
const debug_writer = Writer{ .context = {} };

fn e9_write(_: void, bytes: []const u8) error{}!usize {
    const bytes_left = asm volatile (
        \\cld
        \\rep outsb
        : [ret] "={ecx}" (-> usize),
        : [dest] "{dx}" (0xe9),
          [src] "{esi}" (bytes.ptr),
          [len] "{ecx}" (bytes.len),
    );

    return bytes.len - bytes_left;
}

pub const logger = lib.log.scoped(.Loader);
pub const log_level = lib.log.Level.debug;

pub fn log(comptime level: lib.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
    debug_writer.print(prefix ++ format ++ "\n", args) catch unreachable;
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
