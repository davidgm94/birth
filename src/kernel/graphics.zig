const kernel = @import("kernel.zig");
const Font = kernel.PSF1.Font;

const log = kernel.log.scoped(.graphics);

pub const Framebuffer = struct {
    buffer: [*]u32,
    width: u32,
    height: u32,
};

pub const Point = struct {
    x: u32,
    y: u32,
};

pub const Color = struct {
    red: u8,
    green: u8,
    blue: u8,
    alpha: u8,
};

pub fn draw_char(color: Color, point: Point, character: u8) void {
    log.debug("About to draw char", .{});
    const framebuffer = kernel.framebuffer.buffer[0 .. kernel.framebuffer.width * kernel.framebuffer.height];
    const font_buffer_char_offset = @intCast(u64, character) * kernel.font.header.char_size;
    const font_buffer = kernel.font.glyph_buffer[font_buffer_char_offset .. font_buffer_char_offset + kernel.font.header.char_size];

    for (font_buffer[0..16]) |font_byte, offset_from_y| {
        const y = point.y + offset_from_y;
        var x = point.x;
        const x_max = point.x + 8;

        log.debug("X: {}. Y: {}", .{ x, y });

        while (x < x_max) : (x += 1) {
            if (font_byte & (@as(u8, 0b1000_0000) >> @intCast(u3, x - point.x)) != 0) {
                // TODO: correct the color
                framebuffer[x + (y * kernel.framebuffer.width)] = @bitCast(u32, color);
            }
        }
    }
}
