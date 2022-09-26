const Build = @import("../../../build/lib.zig");

pub const dependency = Build.CObject{
    .dependency = .{
        .type = .c_objects,
        .path = get_path(),
        .dependencies = &.{},
    },
    .objects = &.{"stb_truetype.c"},
};

fn get_path() []const u8 {
    return @src().file;
}
