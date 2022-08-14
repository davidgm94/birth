const std = @import("../../common/std.zig");

const common = switch (std.cpu.arch) {
    .x86_64 => @import("x86_64/common.zig"),
    else => unreachable,
};

pub usingnamespace common;

comptime {
    std.assert(common.page_size == 0x1000);
}

pub const Context = switch (std.cpu.arch) {
    .x86_64 => @import("x86_64/context.zig"),
    else => unreachable,
};

pub const CPU = switch (std.cpu.arch) {
    .x86_64 => @import("x86_64/cpu.zig"),
    else => unreachable,
};

pub const VAS = switch (std.cpu.arch) {
    .x86_64 => @import("x86_64/vas.zig"),
    else => unreachable,
};

comptime {
    if (std.os != .freestanding) @compileError("This file is not meant to be imported in build.zig");
}
