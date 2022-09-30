const common = @import("../../common.zig");

const Graphics = common.Graphics;
const DrawingArea = Graphics.DrawingArea;
const Point = Graphics.Point;

const log = common.log.scoped(.Rectangle);

pub const Int = u32;
pub const side_count = 4;
pub const Rectangle = @Vector(side_count, Int);
pub const Mask = @Vector(side_count, bool);

pub const Component = enum(u3) {
    left = 0,
    right = 1,
    top = 2,
    bottom = 3,
};

pub inline fn component(rectangle: Rectangle, comptime c: Component) Int {
    return rectangle[@enumToInt(c)];
}

pub fn zero() Rectangle {
    return @splat(side_count, @as(Int, 0));
}

pub fn width(rectangle: Rectangle) Int {
    return component(rectangle, .right) - component(rectangle, .left);
}

pub fn height(rectangle: Rectangle) Int {
    return component(rectangle, .bottom) - component(rectangle, .top);
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

    const a_comparison = a;
    const b_comparison = Rectangle{ component(b, .right), component(b, .left), component(b, .bottom), component(b, .top) };
    const result = a_comparison > b_comparison;
    const first_comp = result[0] and result[1];
    const second_comp = result[2] and result[3];
    const mask = @splat(side_count, first_comp or second_comp);

    const if_false_vector = bounding(a, b);

    const final_result = @select(Int, mask, zero_rectangle, if_false_vector);
    return final_result;
}
