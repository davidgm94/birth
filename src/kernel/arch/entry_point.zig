const std = @import("../../common/std.zig");
pub const entry_point = switch (std.cpu.arch) {
    .x86_64 => @import("x86_64/entry_point.zig"),
    else => unreachable,
};

comptime {
    std.reference_all_declarations(entry_point);
}

pub const function = entry_point.function;
