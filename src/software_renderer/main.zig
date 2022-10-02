const std = @import("std");
const SDL = @import("sdl"); // Add this package by using sdk.getWrapperPackage
const common = @import("../common.zig");

const Graphics = common.Graphics;
const Point = Graphics.Point;
const Rectangle = Graphics.Rectangle;
const Rect = Graphics.Rect;
const Framebuffer = Graphics.Framebuffer;

const assert = common.assert;
const log = common.log;

const clamp = common.clamp;

pub const log_level = common.log.Level.debug;

test {
    _ = Rectangle;
}

var window: SDL.Window = undefined;

pub fn main() !void {
    try SDL.init(.{
        .video = true,
        .events = true,
        .audio = true,
    });
    defer SDL.quit();

    window = try SDL.createWindow(
        "SDL2 Wrapper Demo",
        .{ .centered = {} },
        .{ .centered = {} },
        1600,
        900,
        .{ .vis = .shown },
    );
    defer window.destroy();

    const sdl_surface = window.getSurface() catch unreachable;
    var graphics = Graphics.Driver{
        .type = .sdl_software_renderer_prototype,
        .frontbuffer = .{
            .area = .{
                .bytes = @ptrCast([*]u8, sdl_surface.ptr.pixels orelse unreachable),
                .width = @intCast(u32, sdl_surface.ptr.w),
                .height = @intCast(u32, sdl_surface.ptr.h),
                .stride = @intCast(u32, sdl_surface.ptr.pitch),
            },
        },
        .backbuffer = undefined,
        .callback_update_screen = unreachable, //update_backbuffer,
    };

    window_manager.initialize(&graphics);

    const pixel = 0xff_ff_ff_ff;
    const side_pixel_count = 20;
    var surface_buffer = [1]u32{pixel} ** (side_pixel_count * side_pixel_count);
    window_manager.cursor.surface.current = Framebuffer{
        .area = .{
            .bytes = @ptrCast([*]u8, &surface_buffer),
            .width = side_pixel_count,
            .height = side_pixel_count,
            .stride = @sizeOf(u32) * side_pixel_count,
        },
    };

    mainLoop: while (true) {
        defer window_manager.update_screen(&graphics);

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
    initialized: bool,

    fn initialize(manager: *WindowManager, graphics: *Graphics.Driver) void {
        defer manager.initialized = true;
        manager.move_cursor(graphics, @intCast(i32, graphics.frontbuffer.area.width / 2 * Cursor.movement_scale), @intCast(i32, graphics.frontbuffer.area.height / 2 * Cursor.movement_scale));
    }

    fn move_cursor(manager: *WindowManager, graphics: *Graphics, asked_x_movement: i32, asked_y_movement: i32) void {
        const x_movement = asked_x_movement * Cursor.movement_scale;
        const y_movement = asked_y_movement * Cursor.movement_scale;
        manager.cursor.precise_position = .{
            .x = @intCast(u32, clamp(@intCast(i32, manager.cursor.precise_position.x) + @divTrunc(x_movement, Cursor.movement_scale), 0, graphics.frontbuffer.area.width * Cursor.movement_scale - 1)),
            .y = @intCast(u32, clamp(@intCast(i32, manager.cursor.precise_position.y) + @divTrunc(y_movement, Cursor.movement_scale), 0, graphics.frontbuffer.area.height * Cursor.movement_scale - 1)),
        };
        manager.cursor.position = .{
            .x = manager.cursor.precise_position.x / Cursor.movement_scale,
            .y = manager.cursor.precise_position.y / Cursor.movement_scale,
        };
        log.debug("Precise: {}", .{manager.cursor.precise_position});
        log.debug("Position: {}", .{manager.cursor.position});

        manager.update_screen(graphics);
    }

    pub fn update_screen(manager: *WindowManager, graphics: *Graphics.Driver) void {
        const cursor_position = Point{
            .x = manager.cursor.position.x + manager.cursor.image_offset.x,
            .y = manager.cursor.position.y + manager.cursor.image_offset.y,
        };
        const surface_clip = Rectangle.from_area(graphics.framebuffer.area);
        const cursor_area = Rectangle.from_point_and_area(cursor_position, window_manager.cursor.surface.swap.area);
        const cursor_bounds = Rectangle.clip(surface_clip, cursor_area).intersection;
        // TODO: check for resizing

        manager.cursor.surface.swap.copy(graphics.framebuffer, Point{ .x = 0, .y = 0 }, cursor_bounds, true);
        manager.cursor.changed_image = false;

        // todo: alpha mode should be 0xff
        graphics.framebuffer.draw(&manager.cursor.surface.current, Rectangle.from_point_and_area(cursor_position, manager.cursor.surface.current.area), Point{ .x = 0, .y = 0 }, @intToEnum(Graphics.DrawBitmapMode, 0xff));

        if (Rectangle.width(graphics.framebuffer.modified_region) > 0 and Rectangle.height(graphics.framebuffer.modified_region) > 0) {
            const source_area = Graphics.DrawingArea{
                .bytes = graphics.framebuffer.area.bytes + Rectangle.left(graphics.framebuffer.modified_region) * @sizeOf(u32) + Rectangle.top(graphics.framebuffer.modified_region) * graphics.framebuffer.area.stride,
                .width = Rectangle.width(graphics.framebuffer.modified_region),
                .height = Rectangle.height(graphics.framebuffer.modified_region),
                .stride = graphics.framebuffer.area.width * @sizeOf(u32),
            };
            _ = source_area;
            //const destination_point = Point{ .x = Rectangle.left(graphics.framebuffer.modified_region), .y = Rectangle.top(graphics.framebuffer.modified_region) };
            //_ = destination_point;
            if (true) @panic("todo");
            //graphics.callback_update_screen(framebuffer, destination_point);
            //framebuffer.modified_region = .{ framebuffer.area.width, 0, framebuffer.area.height, 0 };
        }

        graphics.framebuffer.copy(&manager.cursor.surface.swap, Point{ .x = Rectangle.left(cursor_bounds), .y = Rectangle.top(cursor_bounds) }, Rectangle.from_width_and_height(Rectangle.width(cursor_bounds), Rectangle.height(cursor_bounds)), true);
    }
};

//fn update_backbuffer(graphics: *Graphics.Driver, source_area: Graphics.DrawingArea, destination_point: Graphics.Point) void {
//_ = graphics;
//const rect = SDL.c.SDL_Rect{
//.x = @intCast(c_int, destination_point.x),
//.y = @intCast(c_int, destination_point.y),
//.w = @intCast(c_int, source_area.width),
//.h = @intCast(c_int, source_area.height),
//};
//const result = SDL.c.SDL_UpdateWindowSurfaceRects(window.ptr, &rect, 1);
//assert(result == 0);
//}

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
