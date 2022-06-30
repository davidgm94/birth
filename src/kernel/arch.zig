const kernel = @import("root");
const common = @import("common");

const current_arch = common.cpu.arch;
const arch = switch (current_arch) {
    .riscv64 => riscv64,
    .x86_64 => x86_64,
    else => @compileError("CPU architecture not supported"),
};

pub const riscv64 = @import("arch/riscv64/riscv64.zig");
pub const x86_64 = @import("arch/x86_64.zig");

pub var writer = common.Writer(void, common.arch.Writer.Error, common.arch.Writer.write){ .context = {} };
