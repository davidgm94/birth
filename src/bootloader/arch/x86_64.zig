const lib = @import("lib");
const assert = lib.assert;
const bootloader = @import("bootloader");
const privileged = @import("privileged");
const paging = privileged.arch.paging;
const x86_64 = privileged.arch.x86_64;

pub const GDT = extern struct {
    null_entry: Entry = Entry.null_entry,
    // 0x08
    code_16: Entry = Entry.code_16,
    // 0x10
    data_16: Entry = Entry.data_16,
    // 0x18
    code_32: Entry = Entry.code_32,
    // 0x20
    data_32: Entry = Entry.data_32,
    // 0x28
    code_64: Entry = Entry.code_64,
    // 0x30
    data_64: Entry = Entry.data_64,

    pub const Entry = x86_64.GDT.Entry;
    pub const Descriptor = x86_64.GDT.Descriptor;

    pub fn getDescriptor(gdt: *const GDT) GDT.Descriptor {
        return .{
            .limit = @sizeOf(GDT) - 1,
            .address = @intFromPtr(gdt),
        };
    }
};

const code_segment_selector = @offsetOf(GDT, "code_64");
const data_segment_selector = @offsetOf(GDT, "data_64");
const entry_point_offset = @offsetOf(bootloader.Information, "entry_point");
const higher_half_offset = @offsetOf(bootloader.Information, "higher_half");

pub fn jumpToKernel(bootloader_information_arg: *bootloader.Information, minimal_paging: paging.Specific) noreturn {
    if (@intFromPtr(bootloader_information_arg) >= lib.config.cpu_driver_higher_half_address) {
        // Error
        privileged.arch.stopCPU();
    }

    // Enable long mode and certain important bits
    var efer = privileged.arch.x86_64.registers.IA32_EFER.read();
    efer.LME = true;
    efer.NXE = true;
    efer.SCE = true;
    efer.write();

    minimal_paging.cr3.write();

    if (lib.cpu.arch == .x86) {
        // Enable PAE
        var cr4 = asm volatile (
            \\mov %cr4, %[cr4]
            : [cr4] "=r" (-> u32),
            :
            : "memory"
        );
        cr4 |= (1 << 5);
        asm volatile (
            \\mov %[cr4], %cr4
            :
            : [cr4] "r" (cr4),
            : "memory"
        );

        // Enable paging
        var cr0 = asm volatile (
            \\mov %cr0, %[cr0]
            : [cr0] "=r" (-> u32),
            :
            : "memory"
        );
        cr0 |= (1 << 31);
        asm volatile (
            \\mov %[cr0], %cr0
            :
            : [cr0] "r" (cr0),
            : "memory"
        );

        asm volatile (
            \\jmp %[code_segment_selector], $bits64
            \\.code64
            \\bits64:
            \\mov %[data_segment_selector], %ds
            \\mov %[data_segment_selector], %es
            \\mov %[data_segment_selector], %fs
            \\mov %[data_segment_selector], %gs
            \\mov %[data_segment_selector], %ss
            :
            : [code_segment_selector] "i" (code_segment_selector),
              [data_segment_selector] "r" (data_segment_selector),
            : "memory"
        );
    }

    switch (lib.cpu.arch) {
        .x86_64 => {
            const bootloader_information = @as(*bootloader.Information, @ptrFromInt(@intFromPtr(bootloader_information_arg) + lib.config.cpu_driver_higher_half_address));
            const entry_point = bootloader_information.entry_point;
            asm volatile (
                \\.code64
                \\jmp *%[entry_point]
                \\cli
                \\hlt
                :
                : [entry_point] "r" (entry_point),
                  [bootloader_information] "{rdi}" (bootloader_information),
                : "memory"
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
              [slice_offset] "i" (@offsetOf(bootloader.Information.Slice, "offset")),
              [slice_size_slide] "i" (@offsetOf(bootloader.Information.Slice, "size") - @offsetOf(bootloader.Information.Slice, "offset")),
              [entry_point_offset] "i" (entry_point_offset),
            : "memory"
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
