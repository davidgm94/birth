const Driver = @This();
const Drivers = @import("common.zig");
const Framebuffer = @import("../common/framebuffer.zig");
const Graphics = @import("graphics.zig");
const kernel = @import("../kernel/kernel.zig");
const Limine = @import("../kernel/arch/x86_64/limine/limine/limine.zig");

graphics: Graphics,
memory_model: u8,
red_mask: ColorMask,
green_mask: ColorMask,
blue_mask: ColorMask,
unused: [7]u8,
edid_size: u64,
edid: u64,

const ColorMask = struct {
    size: u8,
    shift: u8,
};

//pub const Framebuffer = extern struct {
//address: u64,
//width: u64,
//height: u64,
//pitch: u64,
//bpp: u16,
//memory_model: u8,
//red_mask_size: u8,
//red_mask_shift: u8,
//green_mask_size: u8,
//green_mask_shift: u8,
//blue_mask_size: u8,
//blue_mask_shift: u8,
//unused: [7]u8,
//edid_size: u64,
//edid: u64,

pub fn init(framebuffer: Limine.Framebuffer) !void {
    const driver = try kernel.virtual_address_space.heap.allocator.create(Driver);
    driver.* = Driver{
        .graphics = Graphics{
            .type = .limine,
            .framebuffer = Framebuffer{
                .bytes = @intToPtr([*]u8, framebuffer.address),
                .width = framebuffer.width,
                .height = framebuffer.height,
                .stride = framebuffer.bpp * framebuffer.width,
            },
            .callback_update_screen = update_screen,
        },
        .memory_model = framebuffer.memory_model,
        .red_mask = .{ .size = framebuffer.red_mask_size, .shift = framebuffer.red_mask_shift },
        .green_mask = .{ .size = framebuffer.green_mask_size, .shift = framebuffer.green_mask_shift },
        .blue_mask = .{ .size = framebuffer.blue_mask_size, .shift = framebuffer.blue_mask_shift },
        .unused = [1]u8{0} ** 7,
        .edid_size = framebuffer.edid_size,
        .edid = framebuffer.edid,
    };

    try Graphics.init(&driver.graphics);
}

fn update_screen(driver: *Graphics, source_buffer: [*]const u8, source_width: u32, source_height: u32, source_stride: u32, destination_x: u32, destination_y: u32) void {
    _ = driver;
    _ = source_buffer;
    _ = source_width;
    _ = source_height;
    _ = source_stride;
    _ = destination_x;
    _ = destination_y;
    @panic("todo update_screen");
}
