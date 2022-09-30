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

        const source_ptr = @ptrCast([*]u32, @alignCast(@alignOf(u32), source.area.bytes + source.area.stride * Rectangle.top(source_region) + 4 * Rectangle.left(source_region)));
        source.draw_bitmap(surface_clip, destination_region, source_ptr, source.area.stride, .opaque_mode);
    }

    pub fn draw(framebuffer: *Framebuffer, source: *Framebuffer, destination_region: Rect, source_offset: Point, alpha: DrawBitmapMode) void {
        framebuffer.modified_region = Rectangle.bounding(destination_region, framebuffer.modified_region);
        const surface_clip = Rectangle.from_area(framebuffer.area);
        framebuffer.modified_region = Rectangle.intersection(framebuffer.modified_region, surface_clip);
        const source_ptr = @ptrCast([*]u32, @alignCast(@alignOf(u32), source.area.bytes + source.area.stride * source_offset.y + 4 * source_offset.x));
        framebuffer.draw_bitmap(surface_clip, destination_region, source_ptr, source.area.stride, alpha);
    }

    pub fn draw_bitmap(framebuffer: *Framebuffer, clip_area: Rect, region: Rect, source_ptr: [*]const u32, asked_source_stride: u32, mode: DrawBitmapMode) void {
        if (Rectangle.intersect(region, clip_area)) {
            const bounds = Rectangle.intersection_assume_intersects(region, clip_area);
            const source_stride = asked_source_stride / @sizeOf(u32);
            const stride = framebuffer.area.stride / @sizeOf(u32);
            const line_start_index = Rectangle.top(bounds) * stride + Rectangle.left(bounds);
            var line_start = @ptrCast([*]u32, @alignCast(@alignOf(u32), framebuffer.area.bytes)) + line_start_index;
            const source_line_start_index = Rectangle.left(bounds) - Rectangle.left(region) + source_stride * (Rectangle.top(bounds) - Rectangle.top(region));
            var source_line_start = source_ptr + source_line_start_index;

            var i: u64 = 0;
            const bounds_width = Rectangle.width(bounds);
            const bounds_height = Rectangle.height(bounds);

            while (i < bounds_height) : ({
                i += 1;
                line_start += stride;
                source_line_start += source_stride;
            }) {
                var destination = line_start;
                var source = source_line_start;

                var j = bounds_width;
                if (@enumToInt(mode) == 0xff) {
                    @panic("todo");
                } else if (@enumToInt(mode) <= 0xff) {
                    @panic("todo");
                } else if (mode == .xor) {
                    @panic("todo");
                } else if (mode == .opaque_mode) {
                    // todo: refactor
                    while (j > 0) : ({
                        destination += 1;
                        source += 1;
                        j -= 1;
                    }) {
                        destination[0] = 0xff_00_00_00 | source[0];
                    }
                }
            }
        }
    }
};

pub const DrawBitmapMode = enum(u16) {
    blend = 0,
    xor = 0xfffe,
    opaque_mode = 0xffff,
    _,
};
