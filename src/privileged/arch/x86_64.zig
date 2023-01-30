const lib = @import("lib");
const assert = lib.assert;
const cpuid = lib.arch.x86_64.CPUID;

const privileged = @import("privileged");
const AddressInterface = privileged.Address.Interface(u64);
pub const PhysicalAddress = AddressInterface.PhysicalAddress;
pub const VirtualAddress = AddressInterface.VirtualAddress;
pub const PhysicalMemoryRegion = AddressInterface.PhysicalMemoryRegion;
pub const VirtualMemoryRegion = AddressInterface.VirtualMemoryRegion;
pub const PhysicalAddressSpace = AddressInterface.PhysicalAddressSpace;
pub const VirtualAddressSpace = AddressInterface.VirtualAddressSpace(.x86_64);

pub const DescriptorTable = @import("x86/64/descriptor_table.zig");
pub const APIC = @import("x86/64/apic.zig");
pub const GDT = @import("x86/64/gdt.zig");
pub const IDT = @import("x86/64/idt.zig");
pub const io = @import("x86/64/io.zig");
pub const paging = @import("x86/64/paging.zig");
pub const PIC = @import("x86/64/pic.zig");
pub const registers = @import("x86/64/registers.zig");
pub const Syscall = @import("x86/64/syscall.zig");
pub const TSS = @import("x86/64/tss.zig");

pub inline fn stopCPU() noreturn {
    while (true) {
        asm volatile (
            \\cli
            \\hlt
            \\pause
            ::: "memory");
    }
}

pub const dispatch_count = IDT.entry_count - IDT.exception_count;

pub const valid_page_sizes = [3]comptime_int{ 0x1000, 0x1000 * 0x200, 0x1000 * 0x200 * 0x200 };
pub const reverse_valid_page_sizes = blk: {
    var reverse = valid_page_sizes;
    lib.reverse(@TypeOf(valid_page_sizes[0]), &reverse);
    break :blk reverse;
};
pub const page_size = valid_page_sizes[0];
pub const reasonable_page_size = valid_page_sizes[1];

pub fn page_shifter(comptime asked_page_size: comptime_int) comptime_int {
    return @ctz(@as(u32, asked_page_size));
}

pub const CoreDirectorShared = extern struct {
    base: privileged.CoreDirectorSharedGeneric,
    crit_pc_low: VirtualAddress(.local),
    crit_pc_high: VirtualAddress(.local),
    ldt_base: VirtualAddress(.local),
    ldt_page_count: usize,

    enabled_save_area: Registers,
    disabled_save_area: Registers,
    trap_save_area: Registers,
};

pub const Registers = extern struct {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    rsp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: lib.arch.x86_64.registers.RFLAGS,
    fs: u16,
    gs: u16,
    fxsave_area: extern struct {
        fcw: u16,
        fsw: u16,
        ftw: u8,
        reserved1: u8,
        fop: u16,
        fpu_ip1: u32,
        fpu_ip2: u16,
        reserved2: u16,
        fpu_dp1: u32,
        fpu_dp2: u16,
        reserved3: u16,
        mxcsr: u32,
        mxcsr_mask: u32 = 0,
        st: [8][2]u64,
        xmm: [16][2]u64,
        reserved4: [12]u64,
    } align(16),

    comptime {
        assert(@sizeOf(Registers) == 672);
    }

    pub fn set_param(regs: *Registers, param: u64) void {
        regs.rax = param;
    }
};

/// Returns the maximum number bits a physical address is allowed to have in this CPU
pub inline fn get_max_physical_address_bit() u6 {
    return @truncate(u6, cpuid(0x80000008).eax);
}
