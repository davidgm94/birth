const Framebuffer = @import("../common/framebuffer.zig");
const ID = enum {
    limine,
};

pub fn get_framebuffer(bootloader_framebuffer: anytype) Framebuffer {
    const result: Framebuffer = switch (@TypeOf(bootloader_framebuffer)) {
        LimineFramebuffer => .{
            .bytes = @intToPtr([*]u8, bootloader_framebuffer.address),
            .width = bootloader_framebuffer.width,
            .height = bootloader_framebuffer.height,
            .stride = bootloader_framebuffer.bpp * bootloader_framebuffer.width,
        },
        else => @compileError("Framebuffer type not implemented"),
    };

    return result;
}

const LimineFramebuffer = @import("../kernel/arch/x86_64/limine/limine/limine.zig").Framebuffer;
