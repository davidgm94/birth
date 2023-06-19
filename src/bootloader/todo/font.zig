pub const Font = extern struct {
    file: PhysicalMemoryRegion align(8), // so 32-bit doesn't whine
    glyph_buffer_size: u32,
    character_size: u8,
    draw: *const fn (font: *const Font, framebuffer: *const Framebuffer, character: u8, color: u32, offset_x: u32, offset_y: u32) void,

    pub fn fromPSF1(file: []const u8) !Font {
        const header = @as(*const lib.PSF1.Header, @ptrCast(file.ptr));
        if (!lib.equal(u8, &header.magic, &lib.PSF1.Header.magic)) {
            return lib.PSF1.Error.invalid_magic;
        }

        const glyph_buffer_size = @as(u32, header.character_size) * (lib.maxInt(u8) + 1) * (1 + @intFromBool(header.mode == 1));

        return .{
            .file = PhysicalMemoryRegion.new(PhysicalAddress.new(@intFromPtr(file.ptr)), file.len),
            .glyph_buffer_size = glyph_buffer_size,
            .character_size = header.character_size,
            .draw = drawPSF1,
        };
    }

    fn drawPSF1(font: *const Font, framebuffer: *const Framebuffer, character: u8, color: u32, offset_x: u32, offset_y: u32) void {
        const bootloader_information = @fieldParentPtr(Information, "framebuffer", framebuffer);
        const glyph_buffer_virtual_region = if (bootloader_information.stage == .trampoline) font.file.toHigherHalfVirtualAddress() else font.file.toIdentityMappedVirtualAddress();
        const glyph_buffer = glyph_buffer_virtual_region.access(u8)[@sizeOf(lib.PSF1.Header)..][0..font.glyph_buffer_size];
        const glyph_offset = @as(usize, character) * font.character_size;
        const glyph = glyph_buffer[glyph_offset .. glyph_offset + font.character_size];

        var glyph_index: usize = 0;
        _ = glyph_index;

        const pixels_per_scanline = @divExact(framebuffer.pitch, @divExact(framebuffer.bpp, @bitSizeOf(u8)));
        const fb = @as([*]u32, @ptrFromInt(framebuffer.address))[0 .. pixels_per_scanline * framebuffer.height];
        var y = offset_y;

        for (glyph) |byte| {
            const base_index = y * pixels_per_scanline + offset_x;
            if (byte & 1 << 7 != 0) fb[base_index + 0] = color;
            if (byte & 1 << 6 != 0) fb[base_index + 1] = color;
            if (byte & 1 << 5 != 0) fb[base_index + 2] = color;
            if (byte & 1 << 4 != 0) fb[base_index + 3] = color;
            if (byte & 1 << 3 != 0) fb[base_index + 4] = color;
            if (byte & 1 << 2 != 0) fb[base_index + 5] = color;
            if (byte & 1 << 1 != 0) fb[base_index + 6] = color;
            if (byte & 1 << 0 != 0) fb[base_index + 7] = color;

            y += 1;
        }
    }
};
