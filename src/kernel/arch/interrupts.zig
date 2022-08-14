const std = @import("../../common/std.zig");
const arch = switch (std.cpu.arch) {
    .x86_64 => @import("x86_64/interrupts.zig"),
    else => unreachable,
};

comptime {
    if (std.os != .freestanding) @compileError("This file is not supposed to be included in build.zig");
}

pub const enable = arch.enable;
pub const disable = arch.disable;
pub const disable_all = arch.disable_all;
pub const are_enabled = arch.are_enabled;
pub const end = arch.end;
