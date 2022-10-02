const Build = @import("../../../build/lib.zig");

fn get_path() []const u8 {
    return @src().file;
}

pub const dependency = Build.UserProgram{
    .dependency = .{
        .type = .zig_exe,
        .path = get_path(),
        .dependencies = &.{
            Build.Dependency.from_source_file(@import("../../dependencies/stb_truetype/dependency.zig")),
        },
    },
};
