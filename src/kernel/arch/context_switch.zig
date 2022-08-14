const std = @import("../../common/std.zig");

const arch = switch (std.cpu.arch) {
    .x86_64 => @import("x86_64/context_switch.zig"),
    else => unreachable,
};

pub const epilogue = arch.epilogue;
pub const set_new_stack = arch.set_new_stack;
pub const swap_privilege_registers = arch.swap_privilege_registers;
