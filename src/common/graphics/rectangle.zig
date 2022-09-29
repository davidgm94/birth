pub const Int = u32;
pub const Rectangle = @Vector(4, Int);

pub const Component = enum(u3) {
    left = 0,
    right = 1,
    top = 2,
    bottom = 3,
};

pub inline fn component(rectangle: Rectangle, comptime c: Component) Int {
    return rectangle[@enumToInt(c)];
}

pub fn from_width_and_height(width: Int, height: Int) Rectangle {
    return Rectangle{ 0, width, 0, height };
}

pub fn compute_intersection(a: Rectangle, b: Rectangle) Rectangle {
    const zero = @splat(4, @as(u32, 0));

    const result = a > b;
    const first_comp = result[0] and result[1];
    const second_comp = result[2] and result[3];
    const third_comp = @splat(4, first_comp or second_comp);

    const if_false_vector = blk: {
        const max = @maximum(a, b);
        const min = @minimum(a, b);
        const selector_mask = @Vector(4, bool){ true, false, true, false };
        break :blk @select(u32, selector_mask, max, min);
    };

    const final_result = @select(u32, third_comp, zero, if_false_vector);
    return final_result;
}
