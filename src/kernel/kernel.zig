const std = @import("std");
const builtin = @import("builtin");
const logger = std.log.scoped(.init);

pub const current_arch = builtin.cpu.arch;
pub const build_mode = builtin.mode;
pub const arch = @import("arch/riscv.zig");
pub const Memory = @import("memory.zig");
pub usingnamespace @import("assertion.zig");
pub usingnamespace @import("data_manipulation.zig");
const panic_file = @import("panic.zig");
pub const panic = panic_file.panic;
pub const TODO = panic_file.TODO;
pub const bounds = arch.Bounds;

pub const Writer = std.io.Writer;
