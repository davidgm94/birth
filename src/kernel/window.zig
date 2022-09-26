pub const Manager = @This();

const common = @import("common");
const clamp = common.clamp;

const RNU = @import("RNU");
const Graphics = RNU.Graphics;
const Point = Graphics.Point;
const Spinlock = RNU.Spinlock;
const Rectangle = Graphics.Rectangle;

lock: Spinlock = .{},
cursor: Cursor = .{},
initialized: bool = false,

const Cursor = struct {
    position: Position = .{},
    precise_position: Position = .{},
    image_offset: Position = .{},
    properties: Properties = .{},
    surface: struct {
        current: Graphics.Framebuffer = .{},
        swap: Graphics.Framebuffer = .{},
        temporary: Graphics.Framebuffer = .{},
    } = .{},

    pub const movement_scale = 0x100;

    const Properties = packed struct {
        speed: u8 = 1,
    };

    const Position = struct {
        x: u64 = 0,
        y: u64 = 0,
    };
};

pub fn initialize(manager: *Manager, graphics: *Graphics) void {
    manager.lock.acquire();
    defer {
        manager.initialized = true;
        manager.lock.release();
    }

    // Move cursor already updates the screen
    manager.move_cursor(graphics, @intCast(i64, graphics.framebuffer.area.width / 2 * Cursor.movement_scale), @intCast(i64, graphics.framebuffer.area.height / 2 * Cursor.movement_scale));
}

pub fn move_cursor(manager: *Manager, graphics: *Graphics, asked_x_movement: i64, asked_y_movement: i64) void {
    manager.lock.assert_locked();

    // TODO: cursor acceleration

    const x_movement = asked_x_movement * manager.cursor.properties.speed;
    const y_movement = asked_y_movement * manager.cursor.properties.speed;

    // TODO: modifiers
    // TODO: divTrunc?
    manager.cursor.precise_position.x = clamp(@intCast(u64, @intCast(i64, manager.cursor.precise_position.x) + @divTrunc(x_movement, Cursor.movement_scale)), 0, graphics.framebuffer.area.width * Cursor.movement_scale - 1);
    manager.cursor.precise_position.y = clamp(@intCast(u64, @intCast(i64, manager.cursor.precise_position.y) + @divTrunc(y_movement, Cursor.movement_scale)), 0, graphics.framebuffer.area.height * Cursor.movement_scale - 1);
    // TODO: divTrunc?
    manager.cursor.position.x = @divTrunc(manager.cursor.precise_position.x, Cursor.movement_scale);
    manager.cursor.position.y = @divTrunc(manager.cursor.precise_position.y, Cursor.movement_scale);

    // TODO: eyedropping else if window

    manager.update_screen(graphics);
}

pub fn update_screen(manager: *Manager, graphics: *Graphics) void {
    manager.lock.assert_locked();

    // TODO: check for resizing

    const cursor_x = manager.cursor.position.x + manager.cursor.image_offset.x;
    const cursor_y = manager.cursor.position.y + manager.cursor.image_offset.y;
    const bounds = Rectangle{ .left = 0, .right = graphics.framebuffer.area.width, .top = 0, .bottom = graphics.framebuffer.area.height };

    const cursor_bounds = blk: {
        var result = Rectangle{ .left = cursor_x, .right = cursor_x + manager.cursor.surface.swap.area.width, .top = cursor_y, .bottom = cursor_y + manager.cursor.surface.swap.area.height };
        result = result.clip(Rectangle{ .left = 0, .right = bounds.get_width(), .top = 0, .bottom = bounds.get_height() }).rectangle;
        break :blk result;
    };

    manager.cursor.surface.swap.copy(
        &graphics.framebuffer,
        Point{ .x = 0, .y = 0 },
        cursor_bounds,
        true,
    );

    @panic("todo update screen");
    //const cursor_x = manager.
}
