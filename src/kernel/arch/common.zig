const std = @import("../../common/std.zig");

pub const CPU = switch (std.cpu.arch) {
    .x86_64 => @import("x86_64/cpu.zig"),
    else => unreachable,
};
