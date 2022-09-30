const std = @import("std");
const SDL = @import("sdl"); // Add this package by using sdk.getWrapperPackage
const common = @import("../common.zig");
const Graphics = common.Graphics;
const Point = Graphics.Point;
const Rectangle = Graphics.Rectangle;
const Rect = Graphics.Rect;
const Framebuffer = Graphics.Framebuffer;
const log = std.log;

pub const log_level = std.log.Level.debug;

test {
    _ = Rectangle;
}

pub fn main() !void {
    try SDL.init(.{
        .video = true,
        .events = true,
        .audio = true,
    });
    defer SDL.quit();

    var window = try SDL.createWindow(
        "SDL2 Wrapper Demo",
        .{ .centered = {} },
        .{ .centered = {} },
        1600,
        900,
        .{ .vis = .shown },
    );
    defer window.destroy();

    //var prng =
    //std.rand.DefaultPrng.init(blk: {
    //var seed: u64 = undefined;
    //try std.os.getrandom(std.mem.asBytes(&seed));
    //break :blk seed;
    //});
    //const random = prng.random();

    const sdl_surface = window.getSurface() catch unreachable;
    var surface = Framebuffer{
        .area = .{
            .bytes = @ptrCast([*]u8, sdl_surface.ptr.pixels orelse unreachable),
            .width = @intCast(u32, sdl_surface.ptr.w),
            .height = @intCast(u32, sdl_surface.ptr.h),
            .stride = @intCast(u32, sdl_surface.ptr.pitch),
        },
    };

    window_manager.initialize(&surface);

    mainLoop: while (true) {
        defer window.updateSurface() catch unreachable;

        while (SDL.pollEvent()) |ev| {
            switch (ev) {
                .quit => break :mainLoop,
                else => {},
            }
        }
    }
}

var window_manager: WindowManager = undefined;

const WindowManager = struct {
    cursor: Cursor,

    fn initialize(manager: *WindowManager, framebuffer: *Framebuffer) void {
        manager.move_cursor(framebuffer, @intCast(i32, framebuffer.area.width / 2 * Cursor.movement_scale), @intCast(i32, framebuffer.area.height / 2 * Cursor.movement_scale));
    }

    fn move_cursor(manager: *WindowManager, framebuffer: *Framebuffer, asked_x_movement: i32, asked_y_movement: i32) void {
        const x_movement = asked_x_movement * Cursor.movement_scale;
        const y_movement = asked_y_movement * Cursor.movement_scale;
        manager.cursor.precise_position = .{
            .x = @intCast(u32, std.math.clamp(@intCast(i32, manager.cursor.precise_position.x) + @divTrunc(x_movement, Cursor.movement_scale), 0, framebuffer.area.width * Cursor.movement_scale - 1)),
            .y = @intCast(u32, std.math.clamp(@intCast(i32, manager.cursor.precise_position.y) + @divTrunc(y_movement, Cursor.movement_scale), 0, framebuffer.area.height * Cursor.movement_scale - 1)),
        };
        manager.cursor.position = .{
            .x = manager.cursor.precise_position.x / Cursor.movement_scale,
            .y = manager.cursor.precise_position.y / Cursor.movement_scale,
        };
        log.debug("Precise: {}", .{manager.cursor.precise_position});
        log.debug("Position: {}", .{manager.cursor.position});

        manager.update_screen(framebuffer);

        @panic("todo");
    }

    pub fn update_screen(manager: *WindowManager, framebuffer: *Framebuffer) void {
        log.debug("update_screen", .{});
        log.debug("Cursor image offset: {}", .{manager.cursor.image_offset});
        const cursor_position = Point{
            .x = manager.cursor.position.x + manager.cursor.image_offset.x,
            .y = manager.cursor.position.y + manager.cursor.image_offset.y,
        };
        log.debug("Cursor position: {}", .{cursor_position});
        const surface_clip = Rectangle.from_area(framebuffer.area);
        const cursor_area = Rectangle.from_point_and_area(cursor_position, window_manager.cursor.surface.swap.area);
        log.debug("Cursor area: {}", .{cursor_area});
        const cursor_bounds = Rectangle.intersection(surface_clip, cursor_area);
        log.debug("Cursor bounds: {}", .{cursor_bounds});
        // TODO: check for resizing

        manager.cursor.surface.swap.copy(
            Point{ .x = 0, .y = 0 },
            cursor_bounds,
            true,
        );
        manager.cursor.changed_image = false;

        framebuffer.draw(&manager.cursor.surface.current, Rectangle.from_point_and_area(cursor_position, manager.cursor.surface.current.area), Point{ .x = 0, .y = 0 }, @intToEnum(Graphics.DrawBitmapMode, 0xff));

        if (Rectangle.width(framebuffer.modified_region) > 0 and Rectangle.height(framebuffer.modified_region) > 0) {
            const source_area = Graphics.DrawingArea{
                .bytes = framebuffer.area.bytes + Rectangle.left(framebuffer.modified_region) * @sizeOf(u32) + Rectangle.top(framebuffer.modified_region) * framebuffer.area.stride,
                .width = Rectangle.width(framebuffer.modified_region),
                .height = Rectangle.height(framebuffer.modified_region),
                .stride = framebuffer.area.width * @sizeOf(u32),
            };
            const destination_point = Point{ .x = Rectangle.left(framebuffer.modified_region), .y = Rectangle.right(framebuffer.modified_region) };
            _ = source_area;
            _ = destination_point;
            //graphics.callback_update_screen(graphics, source_area, destination_point);
            //graphics.frontbuffer.modified_region = .{ .left = graphics.frontbuffer.area.width, .right = 0, .top = graphics.frontbuffer.area.height, .bottom = 0 };
            //const fb_top = graphics.backbuffer.height * graphics.backbuffer.stride;
            //for (graphics.backbuffer.bytes[0..fb_top]) |fb_byte| {
            //if (fb_byte != 0) {
            //log.debug("NZ: 0x{x}", .{fb_byte});
            //}
            //}
        }
        @panic("todo update screen");

        //if (graphics.frontbuffer.modified_region.width() > 0 and graphics.frontbuffer.modified_region.height() > 0) {
        //}

        //graphics.frontbuffer.copy(&manager.cursor.surface.swap, Point{ .x = cursor_bounds.left, .y = cursor_bounds.top }, Rectangle.from_width_and_height(cursor_bounds.width(), cursor_bounds.height()), true);
    }
};

const Cursor = struct {
    position: Position = .{},
    precise_position: Position = .{},
    image_offset: Position = .{},
    surface: struct {
        current: Graphics.Framebuffer = .{},
        swap: Graphics.Framebuffer = .{},
        temporary: Graphics.Framebuffer = .{},
    } = .{},
    changed_image: bool = false,

    pub const movement_scale = 0x100;

    const Position = Graphics.Point;
};
