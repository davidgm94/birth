const bootloader = @import("bootloader");
pub fn earlyInitialize(bootloader_information: *bootloader.Information) void {
    _ = bootloader_information;
    @panic("TODO: earlyInitialize");
}
