const common = @import("common.zig");

const Allocator = common.Allocator;

pub fn Driver(comptime Generic: type, comptime Specific: type) type {
    // TODO: improve safety
    const child_fields = common.fields(Specific);
    common.comptime_assert(child_fields.len > 0);
    const first_field = child_fields[0];
    common.comptime_assert(first_field.field_type == Generic);

    return struct {
        const log = common.log.scoped(.DriverInitialization);
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
