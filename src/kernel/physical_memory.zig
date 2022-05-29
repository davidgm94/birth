const kernel = @import("kernel.zig");
var map: kernel.Memory.Map = undefined;
pub fn init() void {
    map = kernel.arch.get_memory_map();
}
