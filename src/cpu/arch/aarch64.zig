const bootloader = @import("bootloader");
pub fn earlyInitialize(bootloader_information: *bootloader.Information) void {
    _ = bootloader_information;
    @panic("TODO: earlyInitialize");
}

pub fn entryPoint() callconv(.Naked) noreturn {
    while (true) {}
}