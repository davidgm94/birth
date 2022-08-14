const std = @import("../common/std.zig");

const Allocator = std.Allocator;

pub fn Driver(comptime Generic: type, comptime Specific: type) type {
    // TODO: improve safety
    const child_fields = std.fields(Specific);
    std.comptime_assert(child_fields.len > 0);
    const first_field = child_fields[0];
    std.comptime_assert(first_field.field_type == Generic);

    return struct {
        const log = std.log.scoped(.DriverInitialization);
        const Initialization = Specific.Initialization;

        pub fn init(allocator: Allocator, context: Initialization.Context) Initialization.Error!void {
            const driver = Initialization.callback(allocator, context) catch |err| {
                log.debug("An error ocurred initializating driver {}: {}", .{ Specific, err });
                return err;
            };

            Generic.drivers.append(allocator, @ptrCast(*Generic, driver)) catch return Initialization.Error.allocation_failure;
        }
    };
}
