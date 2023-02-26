const lib = @import("lib");
const assert = lib.assert;
const bootloader = @import("bootloader");
const privileged = @import("privileged");
const GDT = privileged.arch.x86_64.GDT;

const code_segment_selector = @offsetOf(GDT.Table, "code_64");
const data_segment_selector = @offsetOf(GDT.Table, "data_64");
const entry_point_offset = @offsetOf(bootloader.Information, "entry_point");
const higher_half_offset = @offsetOf(bootloader.Information, "higher_half");

pub fn trampoline(bootloader_information_arg: *bootloader.Information) noreturn {
    if (@ptrToInt(bootloader_information_arg) >= lib.config.cpu_driver_higher_half_address) {
        // Error
        privileged.arch.stopCPU();
    }

    // Enable long mode and certain important bits
    var efer = privileged.arch.x86_64.registers.IA32_EFER.read();
    efer.LME = true;
    efer.NXE = true;
    efer.SCE = true;
    efer.write();

    bootloader_information_arg.virtual_address_space.makeCurrent();

    if (lib.cpu.arch == .x86) {
        // Enable PAE
        var cr4 = asm volatile (
            \\mov %%cr4, %[cr4]
            : [cr4] "=r" (-> u32),
        );
        cr4 |= (1 << 5);
        asm volatile (
            \\mov %[cr4], %%cr4 
            :
            : [cr4] "r" (cr4),
        );

        // Enable paging
        var cr0 = asm volatile (
            \\mov %%cr0, %[cr0]
            : [cr0] "=r" (-> u32),
        );
        cr0 |= (1 << 31);
        asm volatile (
            \\mov %[cr0], %%cr0 
            :
            : [cr0] "r" (cr0),
        );
    }

    var gdt_descriptor = bootloader_information_arg.architecture.gdt.getDescriptor();
    if (lib.cpu.arch == .x86) gdt_descriptor.address += lib.config.cpu_driver_higher_half_address;

    asm volatile (
        \\lgdt %[gdt_register]
        :
        : [gdt_register] "*p" (&gdt_descriptor),
    );

    switch (lib.cpu.arch) {
        .x86_64 => {
            _ = asm volatile (
                \\push %[code_segment]
                \\lea trampoline_reload_cs(%rip), %[reload_cs]
                \\push %[reload_cs]
                \\lretq
                \\trampoline_reload_cs:
                : [reload_cs] "=r" (-> u64),
                : [code_segment] "i" (code_segment_selector),
            );
        },
        .x86 => asm volatile (
            \\jmp %[code_segment_selector], $bits64
            \\.code64
            \\bits64:
            :
            : [gdt_register] "*p" (&gdt_descriptor),
              [code_segment_selector] "i" (code_segment_selector),
        ),
        else => @compileError("Architecture not supported"),
    }

    asm volatile (
        \\mov %[data_segment], %ds
        \\mov %[data_segment], %es
        \\mov %[data_segment], %fs
        \\mov %[data_segment], %gs
        \\mov %[data_segment], %ss
        :
        : [data_segment] "r" (data_segment_selector),
    );

    switch (lib.cpu.arch) {
        .x86_64 => {
            const bootloader_information = @intToPtr(*bootloader.Information, @ptrToInt(bootloader_information_arg) + lib.config.cpu_driver_higher_half_address);
            const entry_point = bootloader_information.entry_point;
            const stack_top = bootloader_information.getStackTop();
            asm volatile (
                \\.code64
                \\jmp *%[entry_point]
                \\cli
                \\hlt
                :
                : [entry_point] "r" (entry_point),
                  [stack_top] "{rsp}" (stack_top),
                  [bootloader_information] "{rdi}" (bootloader_information),
            );
        },
        .x86 => asm volatile (
            \\mov %edi, %eax
            \\add %[higher_half_offset], %eax
            \\.byte 0x48
            \\add (%eax), %edi
            \\.byte 0x48
            \\mov %edi, %eax
            \\.byte 0x48
            \\add %[stack_slice_offset], %eax
            \\add %[slice_offset], %eax
            \\mov (%eax), %esp
            \\add %[slice_size_slide], %eax
            \\add (%eax), %esp
            \\.byte 0x48
            \\add %edi, %esp
            // RSP: stack top hh
            \\.byte 0x48
            \\mov %edi, %eax
            \\add %[entry_point_offset], %eax
            \\.byte 0x48
            \\mov (%eax), %eax
            \\jmp *%eax
            \\cli
            \\hlt
            :
            : [bootloader_information] "{edi}" (bootloader_information_arg),
              [higher_half_offset] "i" (higher_half_offset),
              [stack_slice_offset] "i" (comptime bootloader.Information.getStackSliceOffset()),
              [slice_offset] "i" (@offsetOf(bootloader.Information.Slice, "offset")),
              [slice_size_slide] "i" (@offsetOf(bootloader.Information.Slice, "size") - @offsetOf(bootloader.Information.Slice, "offset")),
              [entry_point_offset] "i" (entry_point_offset),
        ),
        else => @compileError("Architecture not supported"),
    }

    unreachable;
}

pub inline fn delay(cycles: u64) void {
    const next_stop = lib.arch.x86_64.readTimestamp() + cycles;
    while (lib.arch.x86_64.readTimestamp() < next_stop) {}
}

pub extern fn smp_trampoline() align(0x1000) callconv(.Naked) noreturn;
