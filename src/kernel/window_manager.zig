const Manager = @This();

const common = @import("common");
const clamp = common.clamp;
const log = common.log.scoped(.WindowManager);

const RNU = @import("RNU");
const Graphics = RNU.Graphics;
const Point = Graphics.Point;
const Spinlock = RNU.Spinlock;
const Rect = Graphics.Rect;
const Rectangle = Graphics.Rectangle;
const Window = RNU.Window;

const kernel = @import("kernel");

const arch = @import("arch");
const TLS = arch.TLS;

lock: Spinlock = .{},
cursor: Cursor = .{},
initialized: bool = false,

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

    const Position = struct {
        x: u32 = 0,
        y: u32 = 0,
    };
};

pub fn initialize(manager: *Manager, graphics: *Graphics.Driver) void {
    manager.lock.acquire();
    defer {
        manager.initialized = true;
        manager.lock.release();
    }

    // Move cursor already updates the screen
    manager.move_cursor(graphics, @intCast(i32, graphics.frontbuffer.area.width / 2 * Cursor.movement_scale), @intCast(i32, graphics.frontbuffer.area.height / 2 * Cursor.movement_scale));
}

pub fn move_cursor(manager: *Manager, graphics: *Graphics.Driver, asked_x_movement: i32, asked_y_movement: i32) void {
    manager.lock.assert_locked();

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

pub fn update_screen(manager: *Manager, graphics: *Graphics.Driver) void {
    manager.lock.assert_locked();

    const cursor_position = Point{
        .x = manager.cursor.position.x + manager.cursor.image_offset.x,
        .y = manager.cursor.position.y + manager.cursor.image_offset.y,
    };
    const surface_clip = Rectangle.from_area(graphics.frontbuffer.area);
    const cursor_area = Rectangle.from_point_and_area(cursor_position, manager.cursor.surface.swap.area);
    const cursor_bounds = Rectangle.clip(surface_clip, cursor_area).intersection;

    manager.cursor.surface.swap.copy(&graphics.frontbuffer, Point{ .x = 0, .y = 0 }, cursor_bounds, true);
    manager.cursor.changed_image = false;

    // todo: alpha mode should be 0xff
    graphics.frontbuffer.draw(&manager.cursor.surface.current, Rectangle.from_point_and_area(cursor_position, manager.cursor.surface.current.area), Point{ .x = 0, .y = 0 }, @intToEnum(Graphics.DrawBitmapMode, 0xff));

    if (Rectangle.width(graphics.frontbuffer.modified_region) > 0 and Rectangle.height(graphics.frontbuffer.modified_region) > 0) {
        const source_area = Graphics.DrawingArea{
            .bytes = graphics.frontbuffer.area.bytes + Rectangle.left(graphics.frontbuffer.modified_region) * @sizeOf(u32) + Rectangle.top(graphics.frontbuffer.modified_region) * graphics.frontbuffer.area.stride,
            .width = Rectangle.width(graphics.frontbuffer.modified_region),
            .height = Rectangle.height(graphics.frontbuffer.modified_region),
            .stride = graphics.frontbuffer.area.width * @sizeOf(u32),
        };
        const destination_point = Point{ .x = Rectangle.left(graphics.frontbuffer.modified_region), .y = Rectangle.top(graphics.frontbuffer.modified_region) };
        graphics.callback_update_screen(graphics, source_area, destination_point);
        graphics.frontbuffer.modified_region = .{ graphics.frontbuffer.area.width, 0, graphics.frontbuffer.area.height, 0 };
    }

    graphics.frontbuffer.copy(&manager.cursor.surface.swap, Point{ .x = Rectangle.left(cursor_bounds), .y = Rectangle.top(cursor_bounds) }, Rectangle.from_width_and_height(Rectangle.width(cursor_bounds), Rectangle.height(cursor_bounds)), true);
}

pub fn create_plain_window(manager: *Manager, user_window: *common.Window) !*Window {
    manager.lock.acquire();
    defer manager.lock.release();

    const window = try kernel.memory.windows.add_one(kernel.virtual_address_space.heap.allocator);
    window.* = Window{ .id = window.id, .user = user_window, .thread = TLS.get_current() };
    return window;
}
