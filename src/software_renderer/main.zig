const std = @import("std");
const SDL = @import("sdl"); // Add this package by using sdk.getWrapperPackage
const common = @import("../common.zig");
const Rectangle = common.Rectangle;
const Rect = Rectangle.Rect;
const log = std.log;

pub const log_level = std.log.Level.info;

pub fn main() !void {
    try SDL.init(.{
        .video = true,
        .events = true,
        .audio = true,
    });
    defer SDL.quit();

    var window = try SDL.createWindow(
        "SDL2 Wrapper Demo",
        .{ .centered = {} },
        .{ .centered = {} },
        640,
        480,
        .{ .vis = .shown },
    );
    defer window.destroy();

    var renderer = try SDL.createRenderer(window, null, .{ .accelerated = false });
    defer renderer.destroy();

    try renderer.setColorRGB(0, 0, 0);
    try renderer.clear();

    const sdl_surface = window.getSurface() catch unreachable;
    const surface = Surface{
        .pixels = @ptrCast([*]u32, @alignCast(@alignOf(u32), sdl_surface.ptr.pixels orelse unreachable)),
        .width = @intCast(u32, sdl_surface.ptr.w),
        .height = @intCast(u32, sdl_surface.ptr.h),
        .pitch = @intCast(u32, sdl_surface.ptr.pitch),
    };
    log.debug("Surface: {}", .{surface});
    //var framerate: f64 = 0;
    //var ms_spent: u64 = 0;
    mainLoop: while (true) {
        //const start = SDL.getTicks64();
        //defer {
        //const end = SDL.getTicks64();
        //const ms = end - start;
        //ms_spent += ms;
        //framerate = (framerate + @intToFloat(f64, ms)) / 2;
        //if (ms_spent > 1000) {
        //log.info("Framerate: {d:0>2}", .{framerate});
        //ms_spent = 0;
        //}
        //}

        while (SDL.pollEvent()) |ev| {
            switch (ev) {
                .quit => break :mainLoop,
                else => {},
            }
        }

        renderer.present();
    }
}

const Surface = struct {
    pixels: [*]u32,
    width: u32,
    height: u32,
    pitch: u32,
};
