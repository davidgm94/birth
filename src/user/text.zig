const STBTrueType = @import("dependencies/stb_truetype/stb_truetype.zig");

const std = @import("../common/std.zig");
const user = @import("common.zig");
pub const logger = std.log.scoped(.Text);

pub const LoadError = error{
    stb_truetype_failed,
};

pub const Font = struct {
    stbtt_font: STBTrueType.FontInfo,

    pub fn create_bitmap_for_text(font: *const Font, text: []const u8, size: f32, bitmap_width: u32, bitmap_height: u32) TextBitmap {
        const scale = STBTrueType.stbtt_ScaleForPixelHeight(&font.stbtt_font, size);
        const bitmap = @import("root").syscall_manager.syscall(.allocate_memory, .blocking, .{ .size = bitmap_width * bitmap_height, .alignment = @alignOf(u32) });
        const vmetrics = font.stbtt_font.get_v_metrics();
        const ascent = @floatToInt(i32, @round(@intToFloat(f32, vmetrics.ascent) * scale));
        //const descent = @round(vmetrics.descent * scale);

        var x: i32 = 0;

        for (text, 0..) |character, index| {
            const hmetrics = font.stbtt_font.get_codepoint_h_metrics(character);
            const codepoint_bitmap_box = font.stbtt_font.get_codepoint_bitmap_box(character, scale, scale);

            const y = ascent + codepoint_bitmap_box.iy0;

            const byte_offset = @intCast(u32, x + @floatToInt(i32, @round(@intToFloat(f32, hmetrics.left_side_bearing) * scale)) + (y * @intCast(i32, bitmap_width)));
            const codepoint_bitmap_width = codepoint_bitmap_box.ix1 - codepoint_bitmap_box.ix0;
            const codepoint_bitmap_height = codepoint_bitmap_box.iy1 - codepoint_bitmap_box.iy0;
            STBTrueType.stbtt_MakeCodepointBitmap(&font.stbtt_font, bitmap[byte_offset..].ptr, codepoint_bitmap_width, codepoint_bitmap_height, @intCast(i32, bitmap_width), scale, scale, character);

            x += @floatToInt(i32, @round(@intToFloat(f32, hmetrics.advance_width) * scale));

            if (index + 1 < text.len) {
                const kern = STBTrueType.stbtt_GetCodepointKernAdvance(&font.stbtt_font, character, text[index + 1]);
                x += @floatToInt(i32, @round(@intToFloat(f32, kern) * scale));
            }
        }

        return TextBitmap{
            .ptr = bitmap.ptr,
            .width = bitmap_width,
            .height = bitmap_height,
        };
    }
};

const TextBitmap = struct {
    ptr: [*]const u8,
    width: u32,
    height: u32,
};

pub fn load_font_from_file(file_content: []const u8) LoadError!Font {
    const stbtt_font = STBTrueType.load_font(file_content) orelse return LoadError.stb_truetype_failed;
    return Font{
        .stbtt_font = stbtt_font,
    };
}
