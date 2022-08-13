const std = @import("../../common/std.zig");
pub usingnamespace switch (std.cpu.arch) {
    .x86_64 => @import("x86_64/context.zig"),
    else => unreachable,
};

comptime {
    if (std.os.tag != .freestanding) @compileError("This file is not supposed to be included in build.zig");
}
