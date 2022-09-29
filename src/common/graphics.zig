pub const Rectangle = @import("graphics/rectangle.zig");
pub const Rect = Rectangle.Rectangle;

pub const DrawingArea = struct {
    bytes: [*]u8 = undefined,
    width: u32 = 0,
    height: u32 = 0,
    stride: u32 = 0,
};
