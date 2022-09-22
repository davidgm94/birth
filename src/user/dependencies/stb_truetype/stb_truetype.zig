const std = @import("../../../common/std.zig");
const log = std.log.scoped(.STBTrueType);
const libc = @import("../../../libc/libc.zig");

// Working way of forcing the exports
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

extern fn stbtt_InitFont(font_info: *FontInfo, data: [*]const u8, offset: c_int) callconv(.C) c_int;
extern fn stbtt_GetCodepointBitmap(font_info: *const FontInfo, scale_x: f32, scale_y: f32, codepoint: c_int, width: *c_int, height: *c_int, xoff: *c_int, yoff: *c_int) callconv(.C) ?[*]const u8;
extern fn stbtt_ScaleForPixelHeight(font_info: *const FontInfo, height: f32) callconv(.C) f32;

pub fn initialize(file: []const u8) void {
    var info: FontInfo = undefined;
    const init_result = stbtt_InitFont(&info, file.ptr, 0);
    log.debug("Init Result: {}", .{init_result});
    var width: c_int = 0;
    var height: c_int = 0;
    var x_offset: c_int = 0;
    var y_offset: c_int = 0;

    const result = stbtt_GetCodepointBitmap(&info, 0, stbtt_ScaleForPixelHeight(&info, 120.0), 'D', &width, &height, &x_offset, &y_offset);
    log.debug("Result: {?*}", .{result});
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
