const lib = @import("lib");

comptime {
    if (lib.os != .freestanding) @compileError("OS not supported");
}

pub const x86_64 = @import("arch/x86_64.zig");

const current = switch (lib.cpu.arch) {
    .x86_64 => x86_64,
    else => @compileError("Architecture not supported"),
};

pub usingnamespace current;

pub const _start = current._start;
