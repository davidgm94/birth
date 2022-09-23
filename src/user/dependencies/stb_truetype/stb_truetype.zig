const std = @import("../../../common/std.zig");
const log = std.log.scoped(.STBTrueType);
const libc = @import("../../../libc/libc.zig");

// Working way of forcing the exports
comptime {
    std.reference_all_declarations(libc);
}

pub const FontInfo = extern struct {
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
    //
    pub fn get_v_metrics(font_info: *const FontInfo) VMetrics {
        var ascent: c_int = 0;
        var descent: c_int = 0;
        var line_gap: c_int = 0;
        stbtt_GetFontVMetrics(font_info, &ascent, &descent, &line_gap);

        return VMetrics{
            .ascent = ascent,
            .descent = descent,
            .line_gap = line_gap,
        };
    }

    pub fn get_codepoint_h_metrics(font_info: *const FontInfo, character: c_int) HMetrics {
        var advance_width: c_int = 0;
        var left_side_bearing: c_int = 0;
        stbtt_GetCodepointHMetrics(font_info, character, &advance_width, &left_side_bearing);

        return HMetrics{
            .advance_width = advance_width,
            .left_side_bearing = left_side_bearing,
        };
    }

    pub fn get_codepoint_bitmap_box(font_info: *const FontInfo, codepoint: c_int, scale_x: f32, scale_y: f32) CodepointBitmapBox {
        var result = CodepointBitmapBox{
            .ix0 = 0,
            .iy0 = 0,
            .ix1 = 0,
            .iy1 = 0,
        };

        stbtt_GetCodepointBitmapBox(font_info, codepoint, scale_x, scale_y, &result.ix0, &result.iy0, &result.ix1, &result.iy1);

        return result;
    }
};

const HMetrics = struct {
    advance_width: i32,
    left_side_bearing: i32,
};

const VMetrics = struct {
    ascent: i32,
    descent: i32,
    line_gap: i32,
};

const CodepointBitmapBox = struct {
    ix0: i32,
    iy0: i32,
    ix1: i32,
    iy1: i32,
};

const Buffer = extern struct {
    data: [*]const u8,
    cursor: c_int,
    size: c_int,
};

pub const CodepointBitmap = struct {
    output: [*]const u8,
    width: u32,
    height: u32,
    stride: i32,
};

pub extern fn stbtt_InitFont(font_info: *FontInfo, data: [*]const u8, offset: c_int) callconv(.C) c_int;
pub extern fn stbtt_GetCodepointBitmap(font_info: *const FontInfo, scale_x: f32, scale_y: f32, codepoint: c_int, width: *c_int, height: *c_int, xoff: *c_int, yoff: *c_int) callconv(.C) ?[*]const u8;
pub extern fn stbtt_ScaleForPixelHeight(font_info: *const FontInfo, height: f32) callconv(.C) f32;
pub extern fn stbtt_GetFontVMetrics(font_info: *const FontInfo, ascent: *c_int, descent: *c_int, line_gap: *c_int) callconv(.C) void;
pub extern fn stbtt_GetCodepointHMetrics(font_info: *const FontInfo, codepoint: c_int, advance_width: *c_int, left_side_bearing: *c_int) callconv(.C) void;
pub extern fn stbtt_GetCodepointBitmapBox(font_info: *const FontInfo, codepoint: c_int, scale_x: f32, scale_y: f32, ix0: *c_int, iy0: *c_int, ix1: *c_int, iy1: *c_int) callconv(.C) void;
pub extern fn stbtt_MakeCodepointBitmap(font_info: *const FontInfo, output: [*]u8, out_w: c_int, out_h: c_int, out_stride: c_int, scale_x: f32, scale_y: f32, codepoint: c_int) callconv(.C) void;
pub extern fn stbtt_GetCodepointKernAdvance(font_info: *const FontInfo, codepoint1: c_int, codepoint2: c_int) callconv(.C) c_int;

pub fn load_font(file: []const u8) ?FontInfo {
    var font: FontInfo = undefined;
    if (stbtt_InitFont(&font, file.ptr, 0) == 0) {
        return null;
    }

    return font;
}

export fn malloc(size: usize) ?*anyopaque {
    const allocation_result = @import("root").syscall_manager.syscall(.allocate_memory, .blocking, .{ .size = size, .alignment = 0x1000 });
    return allocation_result.ptr;
}

// TODO:
export fn free(ptr: ?*anyopaque) void {
    std.log.scoped(.stbtt).debug("TODO free 0x{x}", .{@ptrToInt(ptr)});
}

export fn puts(message: [*:0]const u8) void {
    std.log.scoped(.stbtt).debug("{s}", .{message});
}
