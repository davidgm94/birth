pub const Manager = @This();

const common = @import("common");
const clamp = common.clamp;
const log = common.log.scoped(.WindowManager);

const RNU = @import("RNU");
const Graphics = RNU.Graphics;
const Point = Graphics.Point;
const Spinlock = RNU.Spinlock;
const Rect = Graphics.Rect;
const Rectangle = Graphics.Rectangle;

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

pub fn initialize(manager: *Manager, graphics: *Graphics) void {
    manager.lock.acquire();
    defer {
        manager.initialized = true;
        manager.lock.release();
    }

    // Move cursor already updates the screen
    manager.move_cursor(graphics, @intCast(i32, graphics.frontbuffer.area.width / 2 * Cursor.movement_scale), @intCast(i32, graphics.frontbuffer.area.height / 2 * Cursor.movement_scale));
}

pub fn move_cursor(manager: *Manager, graphics: *Graphics, asked_x_movement: i32, asked_y_movement: i32) void {
    manager.lock.assert_locked();
    log.debug("Asked movement: X: {}. Y: {}", .{ asked_x_movement, asked_y_movement });

    // TODO: cursor acceleration

    const x_movement = asked_x_movement * Cursor.movement_scale;
    const y_movement = asked_y_movement * Cursor.movement_scale;
    log.debug("Computed movement: X: {}. Y: {}", .{ x_movement, y_movement });

    // TODO: modifiers
    // TODO: divTrunc?
    manager.cursor.precise_position.x = blk: {
        const value_to_clamp = @intCast(u32, @intCast(i64, manager.cursor.precise_position.x) + @divTrunc(x_movement, Cursor.movement_scale));
        const clamp_top = graphics.frontbuffer.area.width * Cursor.movement_scale - 1;
        log.debug("value to clamp: {}. Clamp top: {}", .{ value_to_clamp, clamp_top });
        break :blk clamp(value_to_clamp, 0, clamp_top);
    };
    manager.cursor.precise_position.y = blk: {
        const value_to_clamp = @intCast(u32, @intCast(i64, manager.cursor.precise_position.y) + @divTrunc(y_movement, Cursor.movement_scale));
        const clamp_top = graphics.frontbuffer.area.height * Cursor.movement_scale - 1;
        log.debug("value to clamp: {}. Clamp top: {}", .{ value_to_clamp, clamp_top });
        break :blk clamp(value_to_clamp, 0, clamp_top);
    };
    // TODO: divTrunc?
    manager.cursor.position.x = @divTrunc(manager.cursor.precise_position.x, Cursor.movement_scale);
    manager.cursor.position.y = @divTrunc(manager.cursor.precise_position.y, Cursor.movement_scale);

    log.debug("move_cursor: Precise position: {}. Position: {}", .{ manager.cursor.precise_position, manager.cursor.position });

    // TODO: eyedropping else if window

    manager.update_screen(graphics);
}

pub fn update_screen(manager: *Manager, graphics: *Graphics) void {
    manager.lock.assert_locked();

    log.debug("Cursor image offset: {}", .{manager.cursor.image_offset});
    const cursor_x = manager.cursor.position.x + manager.cursor.image_offset.x;
    const cursor_y = manager.cursor.position.y + manager.cursor.image_offset.y;
    const cursor_area = Rect{ cursor_x, cursor_x + manager.cursor.surface.swap.area.width, cursor_y, cursor_y + manager.cursor.surface.swap.area.height };
    log.debug("Cursor area: {}", .{cursor_area});
    const bounds = Rectangle.from_width_and_height(graphics.frontbuffer.area.width, graphics.frontbuffer.area.height);
    const cursor_intersection = Rectangle.compute_intersection(cursor_area, bounds);
    log.debug("Cursor intersection: {}", .{cursor_intersection});
    @panic("todo update screen");
    // TODO: check for resizing

    //const cursor_bounds = blk: {
    //result = result.clip(Rectangle.from_width_and_height(bounds.width(), bounds.height())).rectangle;
    //break :blk result;
    //};

    //manager.cursor.surface.swap.copy(
    //&graphics.frontbuffer,
    //Point{ .x = 0, .y = 0 },
    //cursor_bounds,
    //true,
    //);
    //manager.cursor.changed_image = false;

    //graphics.frontbuffer.draw(&manager.cursor.surface.current, Rectangle{
    //.left = cursor_x,
    //.right = cursor_x + manager.cursor.surface.current.area.width,
    //.top = cursor_y,
    //.bottom = cursor_y + manager.cursor.surface.current.area.height,
    //}, 0, 0, @intToEnum(Graphics.DrawBitmapMode, 0xff));

    //if (graphics.frontbuffer.modified_region.width() > 0 and graphics.frontbuffer.modified_region.height() > 0) {
    //log.debug("Modified region: {}", .{graphics.frontbuffer.modified_region});
    //const source_area = Graphics.DrawingArea{
    //.bytes = graphics.frontbuffer.area.bytes + graphics.frontbuffer.modified_region.left * @sizeOf(u32) + graphics.frontbuffer.modified_region.top * graphics.frontbuffer.area.stride,
    //.width = graphics.frontbuffer.modified_region.width(),
    //.height = graphics.frontbuffer.modified_region.height(),
    //.stride = graphics.frontbuffer.area.width * @sizeOf(u32),
    //};
    //const destination_point = Point{ .x = graphics.frontbuffer.modified_region.left, .y = graphics.frontbuffer.modified_region.right };
    //graphics.callback_update_screen(graphics, source_area, destination_point);
    //graphics.frontbuffer.modified_region = .{ .left = graphics.frontbuffer.area.width, .right = 0, .top = graphics.frontbuffer.area.height, .bottom = 0 };
    //const fb_top = graphics.backbuffer.height * graphics.backbuffer.stride;
    //for (graphics.backbuffer.bytes[0..fb_top]) |fb_byte| {
    //if (fb_byte != 0) {
    //log.debug("NZ: 0x{x}", .{fb_byte});
    //}
    //}
    //}

    //graphics.frontbuffer.copy(&manager.cursor.surface.swap, Point{ .x = cursor_bounds.left, .y = cursor_bounds.top }, Rectangle.from_width_and_height(cursor_bounds.width(), cursor_bounds.height()), true);
}
