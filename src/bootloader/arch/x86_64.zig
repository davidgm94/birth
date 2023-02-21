const lib = @import("lib");
const assert = lib.assert;
const bootloader = @import("bootloader");
const privileged = @import("privileged");
const GDT = privileged.arch.x86_64.GDT;

const code_segment_selector = @offsetOf(GDT.Table, "code_64");
const data_segment_selector = @offsetOf(GDT.Table, "data_64");
pub fn trampoline(bootloader_information_arg: *bootloader.Information) noreturn {
    if (lib.cpu.arch == .x86_64) {
        if (@ptrToInt(bootloader_information_arg) >= lib.config.cpu_driver_higher_half_address) {
            // Error
            privileged.arch.stopCPU();
        }

        var efer = privileged.arch.x86_64.registers.IA32_EFER.read();
        efer.LME = true;
        efer.NXE = true;
        efer.SCE = true;
        efer.write();

        bootloader_information_arg.virtual_address_space.makeCurrent();

        const bootloader_information = @intToPtr(*bootloader.Information, @ptrToInt(bootloader_information_arg) + lib.config.cpu_driver_higher_half_address);
        bootloader_information.stage = .trampoline;

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
              [code_segment] "i" (code_segment_selector),
        );

        asm volatile (
            \\mov %[data_segment], %ds
            \\mov %[data_segment], %es
            \\mov %[data_segment], %fs
            \\mov %[data_segment], %gs
            \\mov %[data_segment], %ss
            :
            : [data_segment] "r" (data_segment_selector),
        );

        asm volatile (
            \\jmp *%[entry_point]
            \\cli
            \\hlt
            :
            : [entry_point] "r" (entry_point),
              [stack_top] "{rsp}" (stack_top),
              [bootloader_information] "{rdi}" (bootloader_information),
        );
    }

    unreachable;
}

pub inline fn delay(cycles: u64) void {
    const next_stop = lib.arch.x86_64.readTimestamp() + cycles;
    while (lib.arch.x86_64.readTimestamp() < next_stop) {}
}

pub extern fn smp_trampoline() align(0x1000) callconv(.Naked) noreturn;
