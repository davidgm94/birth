const std = @import("../common/std.zig");
const DefaultWriter = switch (std.cpu.arch) {
    .x86_64 => @import("arch/x86_64/serial_writer.zig"),
    else => unreachable,
};

const Spinlock = @import("spinlock.zig");

pub var writer = std.Writer(DefaultWriter.Context, DefaultWriter.Error, DefaultWriter.write){ .context = DefaultWriter.Context{} };
pub var lock = Spinlock{};
