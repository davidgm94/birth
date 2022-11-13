const Driver = @This();

const common = @import("common");
const log = common.log.scoped(.LimineGraphics);

const rise = @import("rise");
const Graphics = rise.Graphics;

const kernel = @import("kernel");

const bootloader = @import("bootloader");
const Limine = bootloader.Limine;

graphics: Graphics.Driver,
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

pub fn init(framebuffer: Limine.Framebuffer) !void {
    const driver = try kernel.virtual_address_space.heap.allocator.create(Driver);
    log.debug("Receiving Limine framebuffer: {}", .{framebuffer});

    driver.* = Driver{
        .graphics = Graphics.Driver{
            .type = .limine,
            .backbuffer = Graphics.DrawingArea{
                .bytes = @intToPtr([*]u8, framebuffer.address),
                .width = @intCast(u32, framebuffer.width),
                .height = @intCast(u32, framebuffer.height),
                .stride = @intCast(u32, framebuffer.pitch),
            },
            .frontbuffer = Graphics.Framebuffer{},
            .callback_update_screen = switch (framebuffer.bpp) {
                @bitSizeOf(u32) => update_screen_32,
                else => unreachable,
            },
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

fn update_screen_32(driver: *Graphics.Driver, source: Graphics.DrawingArea, destination_point: Graphics.Point) void {
    Graphics.update_screen_32(driver.backbuffer, source, destination_point);
}
