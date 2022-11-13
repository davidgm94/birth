const common = @import("common");
const assert = common.assert;
const cpuid = common.arch.x86_64.CPUID;

const privileged = @import("privileged");
const VirtualAddress = privileged.VirtualAddress;

pub const DescriptorTable = @import("x86_64/descriptor_table.zig");
pub const APIC = @import("x86_64/apic.zig");
pub const GDT = @import("x86_64/gdt.zig");
pub const IDT = @import("x86_64/idt.zig");
pub const io = @import("x86_64/io.zig");
pub const paging = @import("x86_64/paging.zig");
pub const PIC = @import("x86_64/pic.zig");
pub const registers = @import("x86_64/registers.zig");
pub const Syscall = @import("x86_64/syscall.zig");
pub const TSS = @import("x86_64/tss.zig");

pub inline fn CPU_stop() noreturn {
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
    common.std.mem.reverse(@TypeOf(valid_page_sizes[0]), &reverse);
    break :blk reverse;
};
pub const page_size = valid_page_sizes[0];
pub const reasonable_page_size = valid_page_sizes[1];

pub fn page_shifter(comptime asked_page_size: comptime_int) comptime_int {
    return @ctz(@as(u32, asked_page_size));
}

pub const CoreDirector = struct {
    base: privileged.CoreDirector,
    crit_pc_low: VirtualAddress,
    crit_pc_high: VirtualAddress,
    ldt_base: VirtualAddress,
    ldt_page_count: usize,

    enabled_save_area: Registers,
    disabled_save_area: Registers,
    trap_save_area: Registers,
};
pub const Registers = struct {
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
    rflags: u64,
    fs: u16,
    gs: u16,
    fxsave_area: struct {
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
        mxcsr_mask: u32,
        st: [8][2]u64,
        xmm: [16][2]u64,
        reserved4: [12]u64,
    } align(16),

    comptime {
        assert(@sizeOf(Registers) == 672);
    }
};

/// Returns the maximum number bits a physical address is allowed to have in this CPU
pub inline fn get_max_physical_address_bit() u6 {
    return @truncate(u6, cpuid(0x80000008).eax);
}
