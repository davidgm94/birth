const x86 = @import("x86/common.zig");
pub usingnamespace x86;

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

pub const APIC = @import("x86/64/apic.zig");
pub const io = @import("x86/64/io.zig");
pub const paging = @import("x86/64/paging.zig");
pub const PIC = @import("x86/64/pic.zig");
pub const registers = @import("x86/64/registers.zig");
pub const Syscall = @import("x86/64/syscall.zig");

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

pub const GDT = extern struct {
    pub const Entry = packed struct(u64) {
        limit_low: u16,
        base_low: u16,
        base_mid: u8,
        access: packed struct(u8) {
            accessed: bool,
            read_write: bool,
            direction_conforming: bool,
            executable: bool,
            code_data_segment: bool,
            dpl: u2,
            present: bool,
        },
        limit_high: u4,
        reserved: u1 = 0,
        long_mode: bool,
        size_flag: bool,
        granularity: bool,
        base_high: u8 = 0,

        pub const null_entry = Entry{
            .limit_low = 0,
            .base_low = 0,
            .base_mid = 0,
            .access = .{
                .accessed = false,
                .read_write = false,
                .direction_conforming = false,
                .executable = false,
                .code_data_segment = false,
                .dpl = 0,
                .present = false,
            },
            .limit_high = 0,
            .long_mode = false,
            .size_flag = false,
            .granularity = false,
        };

        pub const code_16 = Entry{
            .limit_low = 0xffff,
            .base_low = 0,
            .base_mid = 0,
            .access = .{
                .accessed = false,
                .read_write = true,
                .direction_conforming = false,
                .executable = true,
                .code_data_segment = true,
                .dpl = 0,
                .present = true,
            },
            .limit_high = 0,
            .long_mode = false,
            .size_flag = false,
            .granularity = false,
        };

        pub const data_16 = Entry{
            .limit_low = 0xffff,
            .base_low = 0,
            .base_mid = 0,
            .access = .{
                .accessed = false,
                .read_write = true,
                .direction_conforming = false,
                .executable = false,
                .code_data_segment = true,
                .dpl = 0,
                .present = true,
            },
            .limit_high = 0,
            .long_mode = false,
            .size_flag = false,
            .granularity = false,
        };

        pub const code_32 = Entry{
            .limit_low = 0xffff,
            .base_low = 0,
            .base_mid = 0,
            .access = .{
                .accessed = false,
                .read_write = true,
                .direction_conforming = false,
                .executable = true,
                .code_data_segment = true,
                .dpl = 0,
                .present = true,
            },
            .limit_high = 0xf,
            .long_mode = false,
            .size_flag = true,
            .granularity = true,
        };

        pub const data_32 = Entry{
            .limit_low = 0xffff,
            .base_low = 0,
            .base_mid = 0,
            .access = .{
                .accessed = false,
                .read_write = true,
                .direction_conforming = false,
                .executable = false,
                .code_data_segment = true,
                .dpl = 0,
                .present = true,
            },
            .limit_high = 0xf,
            .long_mode = false,
            .size_flag = true,
            .granularity = true,
        };

        pub const code_64 = Entry{
            .limit_low = 0xffff,
            .base_low = 0,
            .base_mid = 0,
            .access = .{
                .accessed = false,
                .read_write = true,
                .direction_conforming = false,
                .executable = true,
                .code_data_segment = true,
                .dpl = 0,
                .present = true,
            },
            .limit_high = 0xf,
            .long_mode = true,
            .size_flag = false,
            .granularity = false,
        };

        pub const data_64 = Entry{
            .limit_low = 0xffff,
            .base_low = 0,
            .base_mid = 0,
            .access = .{
                .accessed = false,
                .read_write = true,
                .direction_conforming = false,
                .executable = false,
                .code_data_segment = true,
                .dpl = 0,
                .present = true,
            },
            .limit_high = 0xf,
            .long_mode = false,
            .size_flag = false,
            .granularity = false,
        };

        pub const user_data_64 = Entry{
            .limit_low = 0xffff,
            .base_low = 0,
            .base_mid = 0,
            .access = .{
                .accessed = false,
                .read_write = true,
                .direction_conforming = false,
                .executable = false,
                .code_data_segment = true,
                .dpl = 3,
                .present = true,
            },
            .limit_high = 0xf,
            .long_mode = false,
            .size_flag = true,
            .granularity = true,
        };

        pub const user_code_64 = Entry{
            .limit_low = 0xffff,
            .base_low = 0,
            .base_mid = 0,
            .access = .{
                .accessed = false,
                .read_write = true,
                .direction_conforming = false,
                .executable = true,
                .code_data_segment = true,
                .dpl = 3,
                .present = true,
            },
            .limit_high = 0xf,
            .long_mode = true,
            .size_flag = true,
            .granularity = true,
        };
    };

    pub const Descriptor = x86.SegmentDescriptor;
};

pub const SystemSegmentDescriptor = extern struct {
    pub const Type = enum(u4) {
        ldt = 0b0010,
        tss_available = 0b1001,
        tss_busy = 0b1011,
        call_gate = 0b1100,
        interrupt_gate = 0b1110,
        trap_gate = 0b1111,
    };
};

pub const TSS = extern struct {
    reserved0: u32 = 0,
    rsp: [3]u64 align(4) = [3]u64{ 0, 0, 0 },
    reserved1: u64 align(4) = 0,
    IST: [7]u64 align(4) = [7]u64{ 0, 0, 0, 0, 0, 0, 0 },
    reserved3: u64 align(4) = 0,
    reserved4: u16 = 0,
    IO_map_base_address: u16 = 104,

    comptime {
        assert(@sizeOf(TSS) == 104);
    }

    pub const Descriptor = extern struct {
        limit_low: u16,
        base_low: u16,
        base_mid_low: u8,
        access: Access,
        attributes: Attributes,
        base_mid_high: u8,
        base_high: u32,
        reserved: u32 = 0,

        pub const Access = packed struct(u8) {
            type: SystemSegmentDescriptor.Type,
            reserved: u1 = 0,
            dpl: u2,
            present: bool,
        };

        pub const Attributes = packed struct(u8) {
            limit: u4,
            available_for_system_software: bool,
            reserved: u2 = 0,
            granularity: bool,
        };

        comptime {
            assert(@sizeOf(TSS.Descriptor) == 0x10);
        }
    };

    pub fn getDescriptor(tss: *const TSS, offset: u64) Descriptor {
        const address = @ptrToInt(tss) + offset;
        return Descriptor{
            .low = .{
                .limit_low = @truncate(u16, @sizeOf(TSS) - 1),
                .base_low = @truncate(u16, address),
                .base_low_mid = @truncate(u8, address >> 16),
                .type = 0b1001,
                .descriptor_privilege_level = 0,
                .present = 1,
                .limit_high = 0,
                .available_for_system_software = 0,
                .granularity = 0,
                .base_mid = @truncate(u8, address >> 24),
            },
            .base_high = @truncate(u32, address >> 32),
        };
    }
};
