const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.PhysicalMemoryRegion);

// Barrelfish: memobj
pub const PhysicalMemoryRegion = extern struct {
    size: usize,
    type: Type,

    pub const Type = enum(u8) {
        anonymous = 0,
        one_frame = 1,
        pinned = 3,
        //one_frame_lazy,
        //one_frame_one_map,
        // vfs,
        // fixed,
        // numa,
        // append,

        fn map(t: Type) type {
            return switch (t) {
                .anonymous => Anonymous,
                .one_frame => OneFrame,
                .pinned => Pinned,
            };
        }
    };

    pub const Anonymous = extern struct {
        region: PhysicalMemoryRegion,

        pub usingnamespace Interface(@This());

        pub fn new(size: usize) !Anonymous {
            const result = Anonymous{
                .region = .{
                    .size = size,
                    .type = .anonymous,
                },
            };

            log.warn("[Anonymous.new] TODO: initialize memory", .{});

            return result;
        }
    };

    pub const OneFrame = extern struct {
        pub usingnamespace Interface(@This());
    };

    pub const Pinned = extern struct {
        region: PhysicalMemoryRegion,
        pub usingnamespace Interface(@This());

        pub fn new(size: usize) !Pinned {
            const result = Pinned{
                .region = .{
                    .size = size,
                    .type = .pinned,
                },
            };

            log.warn("[Pinned.new] TODO: initialize memory", .{});

            return result;
        }
    };

    fn Interface(comptime PhysicalMemoryRegionType: type) type {
        assert(@hasField(PhysicalMemoryRegionType, "region"));
        assert(@TypeOf(@field(@as(PhysicalMemoryRegionType, undefined), "region")) == PhysicalMemoryRegion);

        return extern struct {
            pub inline fn getGeneric(r: *PhysicalMemoryRegionType) *PhysicalMemoryRegion {
                return &r.region;
            }
        };
    }
};
