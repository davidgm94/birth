const kernel = @import("../../kernel.zig");
const Physical = @import("physical.zig");
const Virtual = @import("virtual.zig");

pub var enabled = false;

pub fn init() void {
    Physical.init();
    Virtual.init();
    enabled = true;
}
