const std = @import("std");
const builtin = @import("builtin");
const logger = std.log.scoped(.init);

pub const arch = @import("arch/riscv.zig");
