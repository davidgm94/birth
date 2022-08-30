const std = @import("../../common/std.zig");
const libc = @import("../../libc/libc.zig");
const log = std.log.scoped(.STBTrueType);

comptime {
    std.reference_all_declarations(libc);
}

const FontInfo = extern struct {
    user_data: ?*anyopaque,
    data: [*]const u8,
    font_start: c_int,

    num_glyphs: c_int,
    // table locations as offset from start of .ttf
    loca: c_int,
    head: c_int,
    glyf: c_int,
    hhea: c_int,
    hmtx: c_int,
    kern: c_int,
    gpos: c_int,
    svg: c_int,
    index_map: c_int, // a cmap mapping for our chosen character encoding
    indexToLocFormat: c_int, // format needed to map from glyph index to glyph

    cff: Buffer, // cff font data
    charstrings: Buffer, // the charstring index
    gsubrs: Buffer, // global charstring subroutines index
    subrs: Buffer, // private charstring subroutines index
    fontdicts: Buffer, // array of font dicts
    fdselect: Buffer, // map from glyph to fontdict
};

const Buffer = extern struct {
    data: [*]const u8,
    cursor: c_int,
    size: c_int,
};

//STBTT_DEF int stbtt_InitFont(stbtt_fontinfo *info, const unsigned char *data, int offset);
extern fn stbtt_InitFont(font_info: *FontInfo, data: [*]const u8, offset: c_int) callconv(.C) c_int;

pub fn initialize(file: []const u8) void {
    var info: FontInfo = undefined;
    const result = stbtt_InitFont(&info, file.ptr, 0);
    log.debug("Result: {}", .{result});
}
