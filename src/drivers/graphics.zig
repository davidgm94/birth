const Driver = @This();

const std = @import("../common/std.zig");

const common = @import("../kernel/common.zig");
const crash = @import("../kernel/crash.zig");
const Drivers = @import("common.zig");
const DeviceManager = @import("../kernel/device_manager.zig");
const kernel = @import("../kernel/kernel.zig");
const List = @import("../common/list.zig");

const Framebuffer = common.Framebuffer;
const log = std.log.scoped(.graphics);
const StableBuffer = List.StableBuffer;
const TODO = crash.TODO;

const Type = enum(u64) {
    limine = 0,
    virtio = 1,
};

const UpdateScreenFunction = fn (*Driver, source_buffer: [*]const u8, source_width: u32, source_height: u32, source_stride: u32, destination_x: u32, destination_y: u32) void;

type: Type,
framebuffer: Framebuffer,
callback_update_screen: *const UpdateScreenFunction,

pub fn init(driver: *Driver) !void {
    try driver.register();
}

fn register(driver: *Driver) !void {
    try kernel.device_manager.register(Driver, kernel.virtual_address_space.heap.allocator.get_allocator(), driver);

    // TODO: resize surface. Allocate a copy
    kernel.window_manager.initialize(driver);
    // TODO: send a message to the desktop letting it know a graphics device is connected
    @panic("todo");
}

pub const Rectangle = struct {
    left: u64,
    right: u64,
    top: u64,
    bottom: u64,

    pub fn clip(rectangle: Rectangle, current: Rectangle) ?Rectangle {
        const intersection = std.zeroes(Rectangle);

        if (!((current.left > rectangle.right and current.right > rectangle.left) or (current.top > rectangle.bottom and current.bottom > rectangle.top))) {
            intersection.left = if (current.left > rectangle.left) current.left else rectangle.left;
            intersection.right = if (current.right < rectangle.right) current.right else rectangle.right;
            intersection.top = if (current.top > rectangle.top) current.top else rectangle.top;
            intersection.bottom = if (current.bottom < rectangle.bottom) current.bottom else rectangle.bottom;
        } else {
            intersection = {};
        }

        if (intersection.left < intersection.right and intersection.top < intersection.bottom) intersection else return null;
    }
};

pub fn update_screen(user_buffer: [*]u8, bounds: *Rectangle, stride: u64) void {
    _ = user_buffer;
    _ = bounds;
    _ = stride;
    @panic("todo update screen");
}

//// TODO: implement properly
//pub fn get_main_framebuffer(driver: *Driver) *Framebuffer {
//return &driver.framebuffers.first.?.data[driver.primary];
//}

//pub fn draw_horizontal_line(driver: *Driver, line: Line, color: Color) void {
//common.runtime_assert(@src(), line.start.y == line.end.y);
//common.runtime_assert(@src(), line.start.x < line.end.x);
//const length = line.end.x - line.start.x;
//const start_i = line.start.x + (line.start.y * driver.framebuffer.width);
//for (driver.framebuffer.buffer[start_i .. start_i + length]) |*pixel| {
//pixel.* = @bitCast(u32, color);
//}
//}

///// This assumes they are all the same height (start.y and end.y are the same for all of them)
//pub fn draw_parallel_vertical_lines(driver: *Driver, x_coordinates: []u32, height_start: u32, height_end: u32, color: Color) void {
//var y_offset = height_start * driver.framebuffer.width;
//const y_max_offset = height_end * driver.framebuffer.width;

//while (y_offset < y_max_offset) : (y_offset += driver.framebuffer.width) {
//for (x_coordinates) |x| {
//const index = x + y_offset;
//driver.framebuffer.buffer[index] = @bitCast(u32, color);
//}
//}
//}

//pub fn draw_rect(driver: *Driver, rect: Rect, color: Color) void {
//driver.draw_horizontal_line(Line.straight_horizontal(rect.x, rect.y, rect.width), color);
//driver.draw_parallel_vertical_lines(&[_]u32{ rect.x, rect.x + rect.width }, rect.y, rect.y + rect.height, color);
//driver.draw_horizontal_line(Line.straight_horizontal(rect.x, rect.y + rect.height, rect.width), color);
//}

//pub fn test_draw_rect(driver: *Driver) void {
//draw_rect(driver, Rect{
//.x = 600,
//.y = 600,
//.width = 30,
//.height = 60,
//}, Color{ .red = 0, .green = 0, .blue = 0, .alpha = 0 });
//}

//pub const FontFileFormat = enum {
//ttf,
//otf,
//};

//pub fn load_font(driver: *Driver, file: []const u8, file_format: FontFileFormat) void {
//_ = driver;
//_ = file_format;
//log.debug("Font file len: {}", .{file.len});
//unreachable;
//}

////pub const Framebuffer = struct {
////buffer: [*]u32,
////width: u32,
////height: u32,
////cursor: Point,
////};

//pub const Point = struct {
//x: u32,
//y: u32,
//};

//pub const Color = struct {
//red: u8,
//green: u8,
//blue: u8,
//alpha: u8,
//};

//pub const Rect = struct {
//x: u32,
//y: u32,
//width: u32,
//height: u32,
//};

//pub const Line = struct {
//start: Point,
//end: Point,

//fn straight_horizontal(x_start: u32, y: u32, width: u32) Line {
//return Line{
//.start = Point{ .x = x_start, .y = y },
//.end = Point{ .x = x_start + width, .y = y },
//};
//}

//fn straight_vertical(x: u32, y_start: u32, height: u32) Line {
//return Line{
//.start = Point{ .x = x, .y = y_start },
//.end = Point{ .x = x, .y = y_start + height },
//};
//}
//};
