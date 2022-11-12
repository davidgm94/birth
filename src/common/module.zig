const common = @import("../common.zig");
const log = common.log.scoped(.Module);

const len = 64;

pub fn parse(allocator: common.CustomAllocator, file: []const u8) !void {
    _ = allocator;
    var incremental_counter: usize = 0;
    var decremental_counter: usize = file.len;
    while (decremental_counter >= len) {
        log.debug("iteration", .{});
        const v = load_characters(file[incremental_counter .. incremental_counter + len]);
        const ws_mask = whitespace_mask(v);
        _ = ws_mask;
        defer {
            decremental_counter -= len;
            incremental_counter += len;
        }
    }

    @panic("todo parse_configuration_file");
}

pub fn whitespace_mask(characters: @Vector(len, u8)) @Vector(len, u1) {
    const tab = @bitCast(@Vector(len, u1), characters == @splat(len, @as(u8, '\t')));
    const r_linefeed = @bitCast(@Vector(len, u1), characters == @splat(len, @as(u8, '\r')));
    const n_linefeed = @bitCast(@Vector(len, u1), characters == @splat(len, @as(u8, '\n')));
    const whitespace = @bitCast(@Vector(len, u1), characters == @splat(len, @as(u8, ' ')));
    const result = (tab | r_linefeed) | (n_linefeed | whitespace);
    return result;
}

pub fn load_characters(characters: []const u8) @Vector(len, u8) {
    var v = @splat(len, @as(u8, 0));
    for (characters) |ch, i| {
        v[i] = ch;
    }

    return v;
}
