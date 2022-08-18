const PhysicalAddress = @import("physical_address.zig");
const VirtualAddress = @import("virtual_address.zig");

pub const FileInMemory = struct {
    address: VirtualAddress,
    size: u64,
};

pub const Framebuffer = struct {
    virtual_address: VirtualAddress,
    width: u16,
    height: u16,
    bytes_per_pixel: u8,
    red_mask: ColorMask,
    blue_mask: ColorMask,
    green_mask: ColorMask,

    pub fn get_pixel_count(framebuffer: Framebuffer) u32 {
        return @as(u32, framebuffer.width) * framebuffer.height;
    }
};

pub const ColorMask = struct {
    size: u8,
    shift: u8,
};
