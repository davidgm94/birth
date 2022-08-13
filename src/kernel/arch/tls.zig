const std = @import("../../common/std.zig");
const arch = switch (std.cpu.arch) {
    .x86_64 => @import("x86_64/tls.zig"),
    else => unreachable,
};

comptime {
    if (std.os != .freestanding) @compileError("This file is not supposed to be included in build.zig");
}

pub const get_current = arch.get_current;
pub const set_current = arch.set_current;
