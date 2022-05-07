const kernel = @import("kernel.zig");
pub fn Driver(comptime Generic: type, comptime Specific: type) type {
    return struct {
        const log = kernel.log.scoped(.DriverInitialization);
        const Initialization = Specific.Initialization;

        pub fn init(context: Initialization.Context) Initialization.Error!void {
            const driver = Initialization.callback(allocate, context) catch |err| {
                log.debug("An error ocurred initializating driver {}: {}", .{ Specific, err });
                return err;
            };

            // Register the driver
            if (Generic.drivers.len == 0) {
                Generic.drivers.ptr = &Generic._drivers_array;
            }
            const index = Generic.drivers.len;
            Generic.drivers.len += 1;
            Generic.drivers[index] = @ptrCast(*Generic, driver);
        }
    };
}

pub const AllocationCallback = fn (size: u64) ?u64;

fn allocate(size: u64) ?u64 {
    const allocation = kernel.heap.allocate(size, true, true) orelse return null;
    return allocation.virtual;
}
