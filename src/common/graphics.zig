const common = @import("../common.zig");
const assert = common.assert;
const log = common.log.scoped(.Graphics);

pub const Rectangle = @import("graphics/rectangle.zig");
pub const Rect = Rectangle.Rectangle;

pub const DrawingArea = struct {
    bytes: [*]u8 = undefined,
    width: u32 = 0,
    height: u32 = 0,
    stride: u32 = 0,
};

pub const Point = struct {
    x: u32 = 0,
    y: u32 = 0,
};

pub const Framebuffer = struct {
    area: DrawingArea = .{},
    modified_region: Rect = Rectangle.zero(),

    pub fn get_pixel_count(framebuffer: Framebuffer) u32 {
        return framebuffer.area.width * framebuffer.area.height;
    }

    pub fn get_pointer(framebuffer: Framebuffer) [*]u32 {
        return @ptrCast([*]u32, @alignCast(@alignOf(u32), framebuffer.area.bytes));
    }
    pub fn copy(source: *Framebuffer, destination_point: Point, source_region: Rect, add_to_modified_region: bool) void {
        log.debug("copy", .{});
        const destination_region = Rectangle.from_point_and_rectangle(destination_point, source_region);

        const surface_clip = Rectangle.from_area(source.area);

        if (add_to_modified_region) {
            source.modified_region = Rectangle.bounding(destination_region, source.modified_region);
            source.modified_region = Rectangle.intersection(source.modified_region, surface_clip);
        }

        @panic("todo copy");
    }
};
