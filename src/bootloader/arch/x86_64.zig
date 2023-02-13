const lib = @import("../../lib.zig");
const assert = lib.assert;
const log = lib.log.scoped(.Trampoline);
const bootloader = @import("../../bootloader.zig");
const privileged = @import("../../privileged.zig");
const GDT = privileged.arch.x86_64.GDT;

pub fn trampoline(bootloader_information_identity_mapped: *bootloader.Information) noreturn {
    if (@ptrToInt(bootloader_information_identity_mapped) >= lib.config.cpu_driver_higher_half_address) {
        @panic("Bootloader information should be an identity-mapped virtual address when calling the trampoline");
    }

    log.debug("Got to the trampoline", .{});
    const bootloader_information = @intToPtr(*bootloader.Information, @ptrToInt(bootloader_information_identity_mapped) + bootloader_information_identity_mapped.higher_half);
    bootloader_information.virtual_address_space.makeCurrent();
    log.debug("Applied VAS", .{});

    const gdt = GDT.Descriptor{
        .limit = GDT.Table.get_size() - 1,
        .address = @ptrToInt(&bootloader_information.architecture.gdt),
    };

    GDT.Table.load(gdt);
    log.debug("Loaded GDT", .{});

    asm volatile (
        \\cli
        \\hlt
        \\.global trampoline_end
        \\trampoline_end:
    );
    unreachable;
}
extern const trampoline_end: *u8;
pub fn trampolineGetSize() usize {
    return @ptrToInt(&trampoline_end) - @ptrToInt(&trampoline);
}
