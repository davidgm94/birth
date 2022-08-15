const std = @import("../../common/std.zig");
const arch = switch (std.cpu.arch) {
    .x86_64 => @import("x86_64/pci.zig"),
    else => unreachable,
};

pub const read_config = arch.read_config;
pub const write_config = arch.write_config;
