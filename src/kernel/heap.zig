const kernel = @import("kernel.zig");
const TODO = kernel.TODO;

const Region = struct {
    size: u64,
};

regions: [16]?*Region,
// TODO: use another synchronization primitive
lock: kernel.Spinlock,

pub fn allocate(self: *@This()) void {
    self.lock.acquire();
    defer self.lock.release();
    if (self.regions[0] == null) {
        TODO(@src());
    } else {
        TODO(@src());
    }
}
