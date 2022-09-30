const Driver = @This();

const common = @import("common");

pub const DrawingArea = common.Graphics.DrawingArea;
pub const Point = common.Graphics.Point;
pub const Rectangle = common.Graphics.Rectangle;
pub const Rect = common.Graphics.Rect;

const assert = common.assert;
const log = common.log.scoped(.Graphics);
const zeroes = common.zeroes;

const kernel = @import("kernel");

const Type = enum(u64) {
    limine = 0,
    virtio = 1,
};

const UpdateScreenFunction = fn (graphics: *Driver, drawing_area: DrawingArea, destination: Point) void;

type: Type,
frontbuffer: Framebuffer,
backbuffer: DrawingArea,
callback_update_screen: *const UpdateScreenFunction,

pub fn init(driver: *Driver) !void {
    try driver.register();
}

fn register(driver: *Driver) !void {
    log.debug("Registering {}", .{driver.backbuffer});
    try kernel.device_manager.register(Driver, kernel.virtual_address_space.heap.allocator.get_allocator(), driver);

    _ = driver.frontbuffer.resize(driver.backbuffer.width, driver.backbuffer.height);

    // TODO: resize surface. Allocate a copy
    kernel.window_manager.initialize(driver);
    // TODO: send a message to the desktop letting it know a graphics device is connected
    @panic("todo");
}

pub fn update_screen(user_buffer: [*]u8, bounds: *Rectangle, stride: u64) void {
    _ = user_buffer;
    _ = bounds;
    _ = stride;
    @panic("todo update screen");
}

pub const Framebuffer = struct {
    area: DrawingArea = .{},
    modified_region: Rectangle = .{},

    pub fn get_pixel_count(framebuffer: Framebuffer) u32 {
        return framebuffer.area.width * framebuffer.area.height;
    }

    pub fn resize(framebuffer: *Framebuffer, width: u32, height: u32) bool {
        // TODO: copy old bytes
        // TODO: free old bytes
        if (width == 0 or height == 0) return false;

        const old_width = framebuffer.area.width;
        const old_height = framebuffer.area.height;

        if (width == old_width and height == old_height) return true;

        // TODO: stop hardcoding the 4
        const new_buffer_memory = kernel.virtual_address_space.heap.allocator.allocate_bytes(width * height * 4, 0x1000) catch unreachable;
        framebuffer.area = DrawingArea{
            .bytes = @intToPtr([*]u8, new_buffer_memory.address),
            .width = width,
            .height = height,
            .stride = width * 4,
        };

        // Clear it with white to debug it
        framebuffer.fill(0xff_ff_ff_ff);

        return true;
    }

    pub fn fill(framebuffer: *Framebuffer, color: u32) void {
        assert(@divExact(framebuffer.area.stride, framebuffer.area.width) == @sizeOf(u32));

        for (@ptrCast([*]u32, @alignCast(@alignOf(u32), framebuffer.area.bytes))[0..framebuffer.get_pixel_count()]) |*pixel| {
            pixel.* = color;
        }
    }
};

pub fn update_screen_32(destination: DrawingArea, source: DrawingArea, destination_point: Point) void {
    if (destination_point.x > destination.width or source.width > destination.width - destination_point.y or destination_point.y > destination.height or source.height > destination.height - destination_point.y) {
        @panic("out of bounds");
    }

    var destination_row_start = @ptrCast([*]u32, @alignCast(@alignOf(u32), destination.bytes + destination_point.x * @sizeOf(u32) + destination_point.y * destination.stride));
    var source_row_start = @ptrCast([*]const u32, @alignCast(@alignOf(u32), source.bytes));

    var y: u32 = 0;
    while (y < source.height) : ({
        y += 1;
        destination_row_start += destination.stride / @sizeOf(u32);
        source_row_start += source.stride / @sizeOf(u32);
    }) {
        var dst = destination_row_start;
        var src = source_row_start;

        var x: u32 = 0;
        while (x < source.width) : ({
            x += 1;
            dst += 1;
            src += 1;
        }) {
            dst[0] = src[0];
        }
    }
}

pub const DrawBitmapMode = enum(u16) {
    blend = 0,
    xor = 0xfffe,
    opaque_mode = 0xffff,
    _,
};

pub fn draw_bitmap(framebuffer: *Framebuffer, clip_area: Rectangle, region: Rectangle, source_ptr: [*]const u32, asked_source_stride: u32, mode: DrawBitmapMode) void {
    const clip_result = clip_area.clip(region);
    if (!clip_result.result) {
        return;
    }
    const bounds = clip_result.rectangle;

    const source_stride = asked_source_stride / @sizeOf(u32);
    const stride = framebuffer.area.stride / @sizeOf(u32);
    const line_start_index = bounds.top * stride + bounds.left;
    var line_start = @ptrCast([*]u32, @alignCast(@alignOf(u32), framebuffer.area.bytes)) + line_start_index;
    const source_line_start_index = bounds.left - region.left + source_stride * (bounds.top - region.top);
    var source_line_start = source_ptr + source_line_start_index;

    var i: u64 = 0;
    while (i < bounds.bottom - bounds.top) : ({
        i += 1;
        line_start += stride;
        source_line_start += source_stride;
    }) {
        var destination = line_start;
        var source = source_line_start;

        var j = bounds.right - bounds.left;
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
