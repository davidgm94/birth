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

pub fn left(rectangle: Rectangle) Int {
    return rectangle[0];
}
pub fn right(rectangle: Rectangle) Int {
    return rectangle[1];
}
pub fn top(rectangle: Rectangle) Int {
    return rectangle[2];
}
pub fn bottom(rectangle: Rectangle) Int {
    return rectangle[3];
}

pub fn zero() Rectangle {
    return @splat(side_count, @as(Int, 0));
}

pub fn width(rectangle: Rectangle) Int {
    assert(left(rectangle) <= right(rectangle));
    return right(rectangle) - left(rectangle);
}

pub fn height(rectangle: Rectangle) Int {
    assert(top(rectangle) <= bottom(rectangle));
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
    const mask = Mask{ false, true, false, true };
    const result = @select(Int, mask, max, min);

    return result;
}

fn bounding_slow(a: Rectangle, b: Rectangle) Rectangle {
    var result = a;
    if (result[0] > b[0]) result[0] = b[0];
    if (result[2] > b[2]) result[2] = b[2];
    if (result[1] < b[1]) result[1] = b[1];
    if (result[3] < b[3]) result[3] = b[3];
    return result;
}

test "bounding" {
    {
        const a = Rectangle{ 0, 1600, 0, 900 };
        const b = Rectangle{ 800, 800, 450, 450 };
        const expected = bounding_slow(a, b);
        try test_two_rectangles(a, b, expected, bounding);
    }

    {
        const a = Rectangle{ 800, 800, 450, 450 };
        const b = Rectangle{ 0, 0, 0, 0 };
        const expected = bounding_slow(a, b);
        try test_two_rectangles(a, b, expected, bounding);
    }
}

const Clip = struct {
    intersection: Rectangle,
    clip: bool,
};

pub fn clip(a: Rectangle, b: Rectangle) Clip {
    const intersection = blk: {
        if (!((left(a) > right(b) and right(a) > left(b)) or (top(a) > bottom(b) and bottom(a) > top(b)))) {
            break :blk Rectangle{
                if (left(a) > left(b)) left(a) else left(b),
                if (right(a) < right(b)) right(a) else right(b),
                if (top(a) > top(b)) top(a) else top(b),
                if (bottom(a) < bottom(b)) bottom(a) else bottom(b),
            };
        } else {
            break :blk zero();
        }
    };

    return Clip{
        .intersection = intersection,
        .clip = left(intersection) < right(intersection) and top(intersection) < bottom(intersection),
    };
}

test "clip" {
    {
        const a = zero();
        const b = a;
        const expected = Clip{ .intersection = a, .clip = false };
        const result = clip(a, b);
        try common.expect_equal(expected.clip, result.clip);
        try equal(expected.intersection, result.intersection);
    }
    {
        const a = Rectangle{ 800, 800, 450, 450 };
        const b = Rectangle{ 0, 1600, 0, 900 };
        const expected = Clip{ .intersection = a, .clip = false };
        const result = clip(a, b);
        try equal(expected.intersection, result.intersection);
        try common.expect_equal(expected.clip, result.clip);
    }
}

fn equal(a: Rectangle, b: Rectangle) !void {
    var i: u64 = 0;
    while (i < side_count) : (i += 1) {
        try common.expect_equal(a[i], b[i]);
    }
}

fn test_two_rectangles(a: Rectangle, b: Rectangle, expected: Rectangle, comptime function_to_test: fn (Rectangle, Rectangle) Rectangle) !void {
    const result = function_to_test(a, b);

    var i: u64 = 0;
    while (i < side_count) : (i += 1) {
        try common.expect_equal(result[i], expected[i]);
    }
}
