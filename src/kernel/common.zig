const PhysicalAddress = @import("physical_address.zig");
const VirtualAddress = @import("virtual_address.zig");

pub const FileInMemory = struct {
    address: VirtualAddress,
    size: u64,
};

pub const Framebuffer = struct {
    physical_address: PhysicalAddress,
    width: u16,
    height: u16,
    bytes_per_pixel: u8,
    //tag: Tag,
    //framebuffer_addr: u64,
    //framebuffer_width: u16,
    //framebuffer_height: u16,
    //framebuffer_pitch: u16,
    //framebuffer_bpp: u16,
    //memory_model: u8,
    //red_mask_size: u8,
    //red_mask_shift: u8,
    //green_mask_size: u8,
    //green_mask_shift: u8,
    //blue_mask_size: u8,
    //blue_mask_shift: u8,
    //_unused: u8,
};
