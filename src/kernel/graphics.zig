const kernel = @import("kernel.zig");
const Font = kernel.PSF1.Font;

const log = kernel.log.scoped(.graphics);

pub const Framebuffer = struct {
    buffer: [*]u32,
    width: u32,
    height: u32,
    cursor: Point,
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

pub fn draw_string(color: Color, string: []const u8) void {
    for (string) |char| {
        draw_char(color, kernel.framebuffer.cursor, char);
        kernel.framebuffer.cursor.x += 8;

        if (kernel.framebuffer.cursor.x + 8 > kernel.framebuffer.width) {
            kernel.framebuffer.cursor.x = 0;
            kernel.framebuffer.cursor.y += 16;
        }
    }
}

pub const Rect = struct {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
};

pub const Line = struct {
    start: Point,
    end: Point,

    fn straight_horizontal(x_start: u32, y: u32, width: u32) Line {
        return Line{
            .start = Point{ .x = x_start, .y = y },
            .end = Point{ .x = x_start + width, .y = y },
        };
    }

    fn straight_vertical(x: u32, y_start: u32, height: u32) Line {
        return Line{
            .start = Point{ .x = x, .y = y_start },
            .end = Point{ .x = x, .y = y_start + height },
        };
    }
};

pub fn draw_horizontal_line(line: Line, color: Color) void {
    kernel.assert(@src(), line.start.y == line.end.y);
    kernel.assert(@src(), line.start.x < line.end.x);
    const length = line.end.x - line.start.x;
    const start_i = line.start.x + (line.start.y * kernel.framebuffer.width);
    for (kernel.framebuffer.buffer[start_i .. start_i + length]) |*pixel| {
        pixel.* = @bitCast(u32, color);
    }
}

/// This assumes they are all the same height (start.y and end.y are the same for all of them)
pub fn draw_parallel_vertical_lines(x_coordinates: []u32, height_start: u32, height_end: u32, color: Color) void {
    var y_offset = height_start * kernel.framebuffer.width;
    const y_max_offset = height_end * kernel.framebuffer.width;

    while (y_offset < y_max_offset) : (y_offset += kernel.framebuffer.width) {
        for (x_coordinates) |x| {
            const index = x + y_offset;
            kernel.framebuffer.buffer[index] = @bitCast(u32, color);
        }
    }
}

pub fn draw_rect(rect: Rect, color: Color) void {
    draw_horizontal_line(Line.straight_horizontal(rect.x, rect.y, rect.width), color);
    draw_parallel_vertical_lines(&[_]u32{ rect.x, rect.x + rect.width }, rect.y, rect.y + rect.height, color);
    draw_horizontal_line(Line.straight_horizontal(rect.x, rect.y + rect.height, rect.width), color);
}

pub fn test_draw_rect() void {
    draw_rect(Rect{
        .x = 600,
        .y = 600,
        .width = 30,
        .height = 60,
    }, Color{ .red = 0, .green = 0, .blue = 0, .alpha = 0 });
}
