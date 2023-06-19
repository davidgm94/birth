pub const DrawContext = extern struct {
    x: u32 = 0,
    y: u32 = 0,
    color: u32 = 0xff_ff_ff_ff,
    reserved: u32 = 0,

    pub const Error = error{};
    pub const Writer = lib.Writer(*DrawContext, DrawContext.Error, DrawContext.write);

    pub fn write(draw_context: *DrawContext, bytes: []const u8) DrawContext.Error!usize {
        const bootloader_information = @fieldParentPtr(Information, "draw_context", draw_context);
        const color = draw_context.color;
        for (bytes) |byte| {
            if (byte != '\n') {
                bootloader_information.font.draw(&bootloader_information.font, &bootloader_information.framebuffer, byte, color, draw_context.x, draw_context.y);
                if (draw_context.x + 8 < bootloader_information.framebuffer.width) {
                    draw_context.x += @bitSizeOf(u8);
                    continue;
                }
            }

            if (draw_context.y < bootloader_information.framebuffer.width) {
                draw_context.y += bootloader_information.font.character_size;
                draw_context.x = 0;
            } else {
                asm volatile (
                    \\cli
                    \\hlt
                );
            }
        }

        return bytes.len;
    }

    pub inline fn clearScreen(draw_context: *DrawContext, color: u32) void {
        const bootloader_information = @fieldParentPtr(Information, "draw_context", draw_context);
        const pixels_per_scanline = @divExact(bootloader_information.framebuffer.pitch, @divExact(bootloader_information.framebuffer.bpp, @bitSizeOf(u8)));
        const framebuffer_pixels = @as([*]u32, @ptrFromInt(bootloader_information.framebuffer.address))[0 .. pixels_per_scanline * bootloader_information.framebuffer.height];
        var y: u32 = 0;
        while (y < bootloader_information.framebuffer.height) : (y += 1) {
            const line = framebuffer_pixels[y * pixels_per_scanline .. y * pixels_per_scanline + pixels_per_scanline];
            for (line) |*pixel| {
                pixel.* = color;
            }
        }
    }
};
