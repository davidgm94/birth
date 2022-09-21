pub const path = get_path();

fn get_path() []const u8 {
    return @src().file;
}

pub const dependencies = null;
