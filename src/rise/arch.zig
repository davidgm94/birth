const lib = @import("lib");
pub usingnamespace switch (lib.cpu.arch) {
    .x86_64 => x86_64,
    else => @compileError("Architecture not supported"),
};

const x86_64 = @import("arch/x64_64.zig");
