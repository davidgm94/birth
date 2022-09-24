const Framebuffer = @This();

bytes: [*]u8,
width: u64,
height: u64,
stride: u64,

pub fn get_pixel_count(framebuffer: Framebuffer) u32 {
    return @as(u32, framebuffer.width) * framebuffer.height;
}
