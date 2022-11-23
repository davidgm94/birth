const std = @import("std");
comptime {
    asm (
        \\.section .text
        \\.code16
        \\.global hang
        \\hang:
        \\cli
        \\hlt
    );
}

extern fn hang() callconv(.C) noreturn;

pub const cr0 = packed struct(usize) {
    protected_mode_enable: bool = true,
    monitor_coprocessor: bool = false,
    emulation: bool = false,
    task_switched: bool = false,
    extension_type: bool = false,
    numeric_error: bool = false,
    reserved: u10 = 0,
    write_protect: bool = true,
    reserved1: u1 = 0,
    alignment_mask: bool = false,
    reserved2: u10 = 0,
    not_write_through: bool = false,
    cache_disable: bool = false,
    paging: bool = true,
    //upper_32_bits: u32 = 0,

    pub inline fn read() cr0 {
        return asm volatile ("mov %%cr0, %[result]"
            : [result] "=r" (-> cr0),
        );
    }

    pub inline fn write(cr0r: cr0) void {
        asm volatile (
            \\mov %[cr0], %%cr0
            :
            : [cr0] "r" (cr0r),
        );
    }
};

export fn _start() noreturn {
    logger.debug("Hello loader!", .{});
    while (true) {}
}

const Writer = std.io.Writer(void, error{}, e9_write);
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

pub const logger = std.log.scoped(.Loader);
pub const log_level = std.log.Level.debug;

pub fn log(comptime level: std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
    debug_writer.print(prefix ++ format ++ "\n", args) catch unreachable;
}
