const kernel = @import("root");
const common = @import("common");

const arch = switch (common.cpu.arch) {
    .aarch64 => aarch64,
    .x86_64 => x86_64,
    else => @compileError("CPU architecture not supported"),
};
comptime {
    common.reference_all_declarations(arch.entry);
}

pub const aarch64 = @import("arch/aarch64.zig");
pub const x86_64 = @import("arch/x86_64.zig");

pub var writer = common.Writer(void, Writer.Error, Writer.write){ .context = {} };

pub fn Writer(comptime WriterT: type) type {
    return common.Writer(WriterT.Context, WriterT.Error, WriterT.write);
}
