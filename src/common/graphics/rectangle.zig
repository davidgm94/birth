const common = @import("../../common.zig");

const Graphics = common.Graphics;
const DrawingArea = Graphics.DrawingArea;
const Point = Graphics.Point;

const assert = common.assert;
const log = common.log.scoped(.Rectangle);

pub const Int = u32;
pub const side_count = 4;
pub const Rectangle = @Vector(side_count, Int);
pub const Mask = @Vector(side_count, bool);

pub inline fn left(rectangle: Rectangle) Int {
    return rectangle[0];
}
pub inline fn right(rectangle: Rectangle) Int {
    return rectangle[1];
}
pub inline fn top(rectangle: Rectangle) Int {
    return rectangle[2];
}
pub inline fn bottom(rectangle: Rectangle) Int {
    return rectangle[3];
}

pub fn zero() Rectangle {
    return @splat(side_count, @as(Int, 0));
}

pub fn width(rectangle: Rectangle) Int {
    log.debug("R: {}", .{rectangle});
    return right(rectangle) - left(rectangle);
}

pub fn height(rectangle: Rectangle) Int {
    return bottom(rectangle) - top(rectangle);
}

pub fn from_area(area: DrawingArea) Rectangle {
    return from_width_and_height(area.width, area.height);
}

pub fn from_width_and_height(w: Int, h: Int) Rectangle {
    return Rectangle{ 0, w, 0, h };
}

pub fn from_point_and_area(point: Point, area: DrawingArea) Rectangle {
    return Rectangle{ point.x, point.x + area.width, point.y, point.y + area.height };
}

/// This function uses the rectangle width and height as an offset from the specified point
pub fn from_point_and_rectangle(point: Point, rectangle: Rectangle) Rectangle {
    return Rectangle{ point.x, point.x + width(rectangle), point.y, point.y + height(rectangle) };
}

pub fn bounding(a: Rectangle, b: Rectangle) Rectangle {
    const max = @maximum(a, b);
    const min = @minimum(a, b);
    const mask = Mask{ true, false, true, false };
    const result = @select(Int, mask, max, min);

    return result;
}

test "bounding" {
    const a = Rectangle{ 0, 1600, 0, 900 };
    const b = Rectangle{ 800, 800, 450, 450 };
    const expected_result = b;
    const result = bounding(a, b);

    var i: u64 = 0;
    while (i < side_count) : (i += 1) {
        try common.expect(result[i] == expected_result[i]);
    }
}

pub fn intersection(a: Rectangle, b: Rectangle) Rectangle {
    const zero_rectangle = zero();

    const mask = @splat(side_count, intersect(a, b));

    const intersection_if_false = bounding(a, b);

    const final_result = @select(Int, mask, zero_rectangle, intersection_if_false);
    return final_result;
}

pub fn intersect(a: Rectangle, b: Rectangle) bool {
    const a_comparison = a;
    const b_comparison = Rectangle{ right(b), left(b), bottom(b), top(b) };
    const result = a_comparison > b_comparison;
    const first_comp = result[0] and result[1];
    const second_comp = result[2] and result[3];

    return first_comp or second_comp;
}

pub fn intersection_assume_intersects(a: Rectangle, b: Rectangle) Rectangle {
    assert(intersect(a, b));
    return bounding(a, b);
}
