pub const Driver = @This();

const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.Graphics);

pub const Rectangle = @import("graphics/rectangle.zig");
pub const Rect = Rectangle.Rectangle;

const Type = enum(u64) {
    limine = 0,
    virtio = 1,
    sdl_software_renderer_prototype = 2,
};

const UpdateScreenFunction = fn (graphics: *Driver, drawing_area: DrawingArea, destination: Point) void;

type: Type,
frontbuffer: Framebuffer,
backbuffer: DrawingArea,
callback_update_screen: *const UpdateScreenFunction,

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
        return @as([*]u32, @ptrCast(@alignCast(@alignOf(u32), framebuffer.area.bytes)));
    }

    pub fn resize(framebuffer: *Framebuffer, allocator: lib.CustomAllocator, width: u32, height: u32) bool {
        // TODO: copy old bytes
        // TODO: free old bytes
        if (width == 0 or height == 0) return false;

        const old_width = framebuffer.area.width;
        const old_height = framebuffer.area.height;

        if (width == old_width and height == old_height) return true;

        // TODO: stop hardcoding the 4
        const new_buffer_memory = allocator.allocate_bytes(width * height * 4, 0x1000) catch unreachable;
        framebuffer.area = DrawingArea{
            .bytes = @as([*]u8, @ptrFromInt(new_buffer_memory.address)),
            .width = width,
            .height = height,
            .stride = width * 4,
        };

        // Clear it with white to debug it
        framebuffer.fill(0);

        return true;
    }

    pub fn fill(framebuffer: *Framebuffer, color: u32) void {
        assert(@divExact(framebuffer.area.stride, framebuffer.area.width) == @sizeOf(u32));

        for (@as([*]u32, @ptrCast(@alignCast(@alignOf(u32), framebuffer.area.bytes)))[0..framebuffer.get_pixel_count()]) |*pixel| {
            pixel.* = color;
        }
    }

    pub fn copy(framebuffer: *Framebuffer, source: *Framebuffer, destination_point: Point, source_region: Rect, add_to_modified_region: bool) void {
        const destination_region = Rectangle.from_point_and_rectangle(destination_point, source_region);

        const surface_clip = Rectangle.from_area(framebuffer.area);

        if (add_to_modified_region) {
            framebuffer.update_modified_region(destination_region);
        }

        const source_ptr = @as([*]u32, @ptrCast(@alignCast(@alignOf(u32), source.area.bytes + source.area.stride * Rectangle.top(source_region) + 4 * Rectangle.left(source_region))));
        framebuffer.draw_bitmap(surface_clip, destination_region, source_ptr, source.area.stride, .opaque_mode);
    }

    fn update_modified_region(framebuffer: *Framebuffer, destination_region: Rect) void {
        framebuffer.modified_region = Rectangle.bounding(destination_region, framebuffer.modified_region);
        framebuffer.modified_region = Rectangle.clip(framebuffer.modified_region, Rectangle.from_area(framebuffer.area)).intersection;
    }

    pub fn draw(framebuffer: *Framebuffer, source: *Framebuffer, destination_region: Rect, source_offset: Point, alpha: DrawBitmapMode) void {
        const surface_clip = Rectangle.from_area(framebuffer.area);
        framebuffer.update_modified_region(destination_region);
        const source_ptr = @as([*]u32, @ptrCast(@alignCast(@alignOf(u32), source.area.bytes + source.area.stride * source_offset.y + 4 * source_offset.x)));
        framebuffer.draw_bitmap(surface_clip, destination_region, source_ptr, source.area.stride, alpha);
    }

    pub fn draw_bitmap(framebuffer: *Framebuffer, clip_area: Rect, region: Rect, source_ptr: [*]const u32, asked_source_stride: u32, mode: DrawBitmapMode) void {
        const result = Rectangle.clip(region, clip_area);
        if (result.clip) {
            const bounds = result.intersection;
            const source_stride = asked_source_stride / @sizeOf(u32);
            const stride = framebuffer.area.stride / @sizeOf(u32);
            const line_start_index = Rectangle.top(bounds) * stride + Rectangle.left(bounds);
            var line_start = @as([*]u32, @ptrCast(@alignCast(@alignOf(u32), framebuffer.area.bytes))) + line_start_index;
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
                if (@intFromEnum(mode) == 0xff) {
                    while (true) {
                        blend_pixel(&destination[0], source[0]);
                        destination += 1;
                        source += 1;
                        j -= 1;
                        if (j == 0) break;
                    }
                } else if (@intFromEnum(mode) <= 0xff) {
                    @panic("todo: mode <= 0xff");
                } else if (mode == .xor) {
                    @panic("todo: mode xor");
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

// TODO: full alpha
fn blend_pixel(destination_pixel: *u32, modified: u32) void {
    if (modified & 0xff_00_00_00 == 0xff_00_00_00) {
        destination_pixel.* = modified;
        return;
    } else if (modified & 0xff_00_00_00 == 0) {
        return;
    }

    const original = destination_pixel.*;

    const m1 = (modified & 0xff_00_00_00) >> 24;
    const m2 = 255 - m1;
    const a = 0xff_00_00_00;

    const r2 = m2 * (original & 0x00FF00FF);
    const g2 = m2 * (original & 0x0000FF00);
    const r1 = m1 * (modified & 0x00FF00FF);
    const g1 = m1 * (modified & 0x0000FF00);
    const result = a | (0x0000FF00 & ((g1 + g2) >> 8)) | (0x00FF00FF & ((r1 + r2) >> 8));
    destination_pixel.* = result;
}

pub const DrawBitmapMode = enum(u16) {
    blend = 0,
    xor = 0xfffe,
    opaque_mode = 0xffff,
    _,
};
