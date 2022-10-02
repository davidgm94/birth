const common = @import("common");
const Graphics = common.Graphics;
pub usingnamespace Graphics;

const assert = common.assert;
const log = common.log.scoped(.Graphics);
const zeroes = common.zeroes;

const kernel = @import("kernel");

pub fn init(driver: *Graphics.Driver) !void {
    try register(driver);
}

fn register(driver: *Graphics.Driver) !void {
    log.debug("Registering {}", .{driver.backbuffer});
    try kernel.device_manager.register(Graphics.Driver, kernel.virtual_address_space.heap.allocator.get_allocator(), driver);

    _ = driver.frontbuffer.resize(kernel.virtual_address_space.heap.allocator, driver.backbuffer.width, driver.backbuffer.height);

    // TODO: resize surface. Allocate a copy
    kernel.window_manager.initialize(driver);
    // TODO: send a message to the desktop letting it know a graphics device is connected
}

pub fn update_screen(user_buffer: [*]u8, bounds: *Graphics.Rectangle, stride: u64) void {
    _ = user_buffer;
    _ = bounds;
    _ = stride;
    @panic("todo update screen");
}

//pub const Framebuffer = struct {
//area: DrawingArea = .{},
//modified_region: Rectangle = .{},

//pub fn get_pixel_count(framebuffer: Framebuffer) u32 {
//return framebuffer.area.width * framebuffer.area.height;
//}

//};

pub fn update_screen_32(destination: Graphics.DrawingArea, source: Graphics.DrawingArea, destination_point: Graphics.Point) void {
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
