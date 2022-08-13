const std = @import("../common/std.zig");
comptime {
    std.reference_all_declarations(arch.entry);
}

const arch = switch (std.cpu.arch) {
    .aarch64 => aarch64,
    .x86_64 => x86_64,
    else => @compileError("CPU architecture not supported"),
};

pub const Context = arch.Context;
pub const CPU = arch.CPU;
pub const DefaultWriter = arch.DefaultWriter;
pub const get_current_thread = arch.get_current_thread;
pub const Spinlock = arch.Spinlock;
pub const VAS = arch.VAS;

pub var default_io = Writer(DefaultWriter){};

pub fn Writer(comptime WriterT: type) type {
    const StandardWriterType = std.Writer(WriterT.Context, WriterT.Error, WriterT.write);
    return struct {
        writer: StandardWriterType = .{ .context = WriterT.Context{} },
        lock: Spinlock = .{},
    };
}

pub const aarch64 = @import("arch/aarch64.zig");
pub const x86_64 = @import("arch/x86_64.zig");
