const Framebuffer = @This();

virtual_address: u64,
width: u64,
height: u64,
bytes_per_pixel: u8,
red_mask: ColorMask,
blue_mask: ColorMask,
green_mask: ColorMask,

pub fn get_pixel_count(framebuffer: Framebuffer) u32 {
    return @as(u32, framebuffer.width) * framebuffer.height;
}

pub const ColorMask = struct {
    size: u8,
    shift: u8,
};
