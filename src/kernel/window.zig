pub const Manager = @This();

const std = @import("../common/std.zig");

const Graphics = @import("../drivers/graphics.zig");
const Spinlock = @import("spinlock.zig");

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
        current: Framebuffer,
        swap: Framebuffer,
        temporary: Framebuffer,
    },

    pub const movement_scale = 0x100;

    const Properties = packed struct {
        speed: u8 = 1,
    };

    const Position = struct {
        x: i64 = 0,
        y: i64 = 0,
    };
};

pub fn initialize(manager: *Manager, graphics: *Graphics) void {
    manager.lock.acquire();
    defer {
        manager.initialized = true;
        manager.lock.release();
    }

    // Move cursor already updates the screen
    manager.move_cursor(graphics, @intCast(i64, graphics.framebuffer.width / 2 * Cursor.movement_scale), @intCast(i64, graphics.framebuffer.height / 2 * Cursor.movement_scale));
}

pub fn move_cursor(manager: *Manager, graphics: *Graphics, asked_x_movement: i64, asked_y_movement: i64) void {
    manager.lock.assert_locked();

    // TODO: cursor acceleration

    const x_movement = asked_x_movement * manager.cursor.properties.speed;
    const y_movement = asked_y_movement * manager.cursor.properties.speed;

    // TODO: modifiers
    // TODO: divTrunc?
    manager.cursor.precise_position.x = std.clamp(manager.cursor.precise_position.x + @divTrunc(x_movement, Cursor.movement_scale), 0, graphics.framebuffer.width * Cursor.movement_scale - 1);
    manager.cursor.precise_position.y = std.clamp(manager.cursor.precise_position.y + @divTrunc(y_movement, Cursor.movement_scale), 0, graphics.framebuffer.height * Cursor.movement_scale - 1);
    // TODO: divTrunc?
    manager.cursor.position.x = @divTrunc(manager.cursor.precise_position.x, Cursor.movement_scale);
    manager.cursor.position.y = @divTrunc(manager.cursor.precise_position.y, Cursor.movement_scale);

    // TODO: eyedropping else if window

    manager.update_screen(graphics);
}

pub fn update_screen(manager: *Manager, graphics: *Graphics) void {
    manager.lock.assert_locked();
    _ = graphics;

    // TODO: check for resizing

    const cursor_x = manager.cursor.position.x + manager.cursor.image_offset.x;
    const cursor_y = manager.cursor.position.y + manager.cursor.image_offset.y;
    const rectangle = Rectangle { .left = 0, .right = graphics.framebuffer.width, .top = 0, .bottom = graphics.framebuffer.height };

    const cursor_bounds = Rectangle{ .left = cursor_x, .right = cursor_x + manager.cursor.surface.swap, .top = cursor_y, .bottom = cursor_y + manager.cursor.surface.height };

    @panic("todo update screen");
    //const cursor_x = manager.
}
