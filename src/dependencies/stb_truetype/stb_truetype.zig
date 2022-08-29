const std = @import("../../common/std.zig");
const libc = @import("../../libc/libc.zig");

comptime {
    std.reference_all_declarations(libc);
}
