const lib = @import("lib");

const current = switch (lib.cpu.arch) {
    .x86_64 => @import("arch/x86_64.zig"),
    else => @compileError("Architecture not supported"),
};
pub usingnamespace current;

pub const entryPoint = current.entryPoint;
pub const virtualAddressSpaceallocatePages = current.virtualAddressSpaceallocatePages;
