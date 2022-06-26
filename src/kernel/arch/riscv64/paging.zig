const kernel = @import("kernel");
const Physical = @import("physical.zig");
const Virtual = @import("virtual.zig");

pub var enabled = false;

pub fn init() void {
    Physical.init();
    Virtual.init();
    enabled = true;
}
