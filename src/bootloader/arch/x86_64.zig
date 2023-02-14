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

    const bootloader_information_higher_half = @ptrToInt(bootloader_information_identity_mapped) + bootloader_information_identity_mapped.higher_half;
    bootloader_information_identity_mapped.virtual_address_space.makeCurrent();

    const bootloader_information = @intToPtr(*bootloader.Information, bootloader_information_higher_half);

    const stack_top = bootloader_information.getStackTop();
    const entry_point = bootloader_information.entry_point;
    const gdt = GDT.Descriptor{
        .limit = GDT.Table.get_size() - 1,
        .address = @ptrToInt(&bootloader_information.architecture.gdt),
    };

    _ = asm volatile (
        \\lgdt %[gdt_register]
        \\push %[code_segment]
        \\lea trampoline_reload_cs(%rip), %[reload_cs]
        \\push %[reload_cs]
        \\lretq
        \\trampoline_reload_cs:
        : [reload_cs] "=r" (-> u64),
        : [gdt_register] "*p" (&gdt),
          [code_segment] "i" (@offsetOf(GDT.Table, "code_64")),
    );

    asm volatile (
        \\mov %[data_segment], %ds
        \\mov %[data_segment], %es
        \\mov %[data_segment], %fs
        \\mov %[data_segment], %gs
        \\mov %[data_segment], %ss
        \\jmp *%[entry_point]
        \\cli
        \\hlt
        \\.global trampoline_end
        \\trampoline_end:
        :
        : [data_segment] "r" (@offsetOf(GDT.Table, "data_64")),
          [entry_point] "r" (entry_point),
          [stack_top] "{rsp}" (stack_top),
          [bootloader_information] "{rdi}" (bootloader_information),
    );

    unreachable;
}

extern const trampoline_end: *u8;
pub fn trampolineGetSize() usize {
    return @ptrToInt(&trampoline_end) - @ptrToInt(&trampoline);
}
