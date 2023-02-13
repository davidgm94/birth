const bootloader = @import("../../../../bootloader.zig");

/// System V ABI declared here to avoid UEFI's callconv(.C) being MSVC ABI
const higher_half_offset = @offsetOf(bootloader.Information, "higher_half");
const cr3_offset = @offsetOf(bootloader.Information, "virtual_address_space") + @offsetOf(bootloader.VirtualAddressSpace, "arch") + @offsetOf(bootloader.VirtualAddressSpace.paging.Specific, "cr3");

pub const function = trampoline;
pub extern fn trampoline(bootloader_information: *bootloader.Information) callconv(.SysV) noreturn;
extern const trampoline_end: *u8;
pub fn getSize() usize {
    return @ptrToInt(&trampoline_end) - @ptrToInt(&trampoline);
}
export fn trampolineNaked() callconv(.Naked) noreturn {
    // RDI: bootloader information
    asm volatile (
        \\.global trampoline
        \\trampoline:
        \\mov $0xffff800000000000, %rax
        \\cmp %rax, %rdi
        \\jnb trampoline_error
        \\mov %rdi, %rax
        \\add %[hh_offset], %rax
        // RBX: HH
        \\mov (%rax), %rbx 
        \\mov %rdi, %rax
        \\add %[cr3_offset], %rax
        // RCX: cr3
        \\mov (%rax), %rax
        \\mov %rax, %cr3
        \\trampoline_error:
        \\cli
        \\hlt
        \\.global trampoline_end
        \\trampoline_end:
        :
        : [hh_offset] "i" (higher_half_offset),
          [cr3_offset] "i" (cr3_offset),
    );

    unreachable;
}
