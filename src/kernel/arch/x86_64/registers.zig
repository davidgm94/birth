const common = @import("common");
const assert = common.assert;

const privileged = @import("privileged");
const PhysicalAddress = privileged.PhysicalAddress;

const arch = @import("arch");
const x86_64 = arch.x86_64;

const SimpleRegister = enum {
    rax,
    rbx,
    rcx,
    rdx,
    rbp,
    rsp,
    rsi,
    rdi,
    r8,
    r9,
    r10,
    r11,
    r12,
    r13,
    r14,
    r15,

    gs,
    cs,

    dr0,
    dr1,
    dr2,
    dr3,
    dr4,
    dr5,
    dr6,
    dr7,

    cr2,
    cr8,
};

pub const ComplexRegister = enum { cr0, cr3, cr4 };

pub const rax = SimpleR64(.rax);
pub const rbx = SimpleR64(.rbx);
pub const rcx = SimpleR64(.rcx);
pub const rdx = SimpleR64(.rdx);
pub const rbp = SimpleR64(.rbp);
pub const rsp = SimpleR64(.rsp);
pub const rsi = SimpleR64(.rsi);
pub const rdi = SimpleR64(.rdi);
pub const r8 = SimpleR64(.r8);
pub const r9 = SimpleR64(.r9);
pub const r10 = SimpleR64(.r10);
pub const r11 = SimpleR64(.r11);
pub const r12 = SimpleR64(.r12);
pub const r13 = SimpleR64(.r13);
pub const r14 = SimpleR64(.r14);
pub const r15 = SimpleR64(.r15);

pub const gs = SimpleR64(.gs);
pub const cs = SimpleR64(.cs);

pub const dr0 = SimpleR64(.dr0);
pub const dr1 = SimpleR64(.dr1);
pub const dr2 = SimpleR64(.dr2);
pub const dr3 = SimpleR64(.dr3);
pub const dr4 = SimpleR64(.dr4);
pub const dr5 = SimpleR64(.dr5);
pub const dr6 = SimpleR64(.dr6);
pub const dr7 = SimpleR64(.dr7);

/// Contains system control flags that control operating mode and states of the processor.
pub const cr0 = packed struct(usize) {
    protected_mode_enable: bool = true,
    monitor_coprocessor: bool = false,
    emulation: bool = false,
    task_switched: bool = false,
    extension_type: bool = false,
    numeric_error: bool = false,
    reserved: u10 = 0,
    write_protect: bool = true,
    reserved1: u1 = 0,
    alignment_mask: bool = false,
    reserved2: u10 = 0,
    not_write_through: bool = false,
    cache_disable: bool = false,
    paging: bool = true,
    upper_32_bits: u32 = 0,

    pub inline fn read() cr0 {
        return asm volatile ("mov %%cr0, %[result]"
            : [result] "=r" (-> cr0),
        );
    }

    pub inline fn write(cr0r: cr0) void {
        asm volatile (
            \\mov %[cr0], %%cr0
            :
            : [cr0] "r" (cr0r),
        );
    }
};

/// Contains the page-fault linear address (the linear address that caused a page fault).
pub const cr2 = SimpleR64(.cr2);

/// WARNING: this data structure is only set to be used for 40-bit max physical address bit
pub const cr3 = packed struct(usize) {
    reserved0: u3 = 0,
    /// Page-level Write-Through (bit 3 of CR3) — Controls the memory type used to access the first paging
    /// structure of the current paging-structure hierarchy. See Section 4.9, “Paging and Memory Typing”. This bit
    /// is not used if paging is disabled, with PAE paging, or with 4-level paging or 5-level paging if CR4.PCIDE=1.
    PWT: bool = false,

    /// Page-level Cache Disable (bit 4 of CR3) — Controls the memory type used to access the first paging
    /// structure of the current paging-structure hierarchy. See Section 4.9, “Paging and Memory Typing”. This bit
    /// is not used if paging is disabled, with PAE paging, or with 4-level paging1 or 5-level paging if CR4.PCIDE=1.
    PCD: bool = false,
    reserved1: u7 = 0,
    address: u52 = 0, // get this to be 32-bit compatible

    comptime {
        assert(@sizeOf(cr3) == @sizeOf(usize));
        assert(@bitSizeOf(cr3) == @bitSizeOf(usize));
    }

    pub fn from_address(physical_address: PhysicalAddress) cr3 {
        const PackedAddressType = blk: {
            var foo_cr3: cr3 = undefined;
            break :blk @TypeOf(@field(foo_cr3, "address"));
        };

        return .{
            .address = @intCast(PackedAddressType, physical_address.value >> @bitOffsetOf(cr3, "address")),
        };
    }

    pub inline fn read() cr3 {
        return asm volatile ("mov %%cr3, %[result]"
            : [result] "=r" (-> cr3),
        );
    }

    pub inline fn write(value: cr3) void {
        asm volatile ("mov %[in], %%cr3"
            :
            : [in] "r" (value),
        );
    }

    pub inline fn equal(self: cr3, other: cr3) bool {
        const self_int = @bitCast(usize, self);
        const other_int = @bitCast(usize, other);
        return self_int == other_int;
    }

    pub inline fn get_address(self: cr3) PhysicalAddress {
        return PhysicalAddress.new(@as(usize, self.address) << @bitOffsetOf(cr3, "address"));
    }
};

/// Contains a group of flags that enable several architectural extensions, and indicate operating system or
/// executive support for specific processor capabilities. Bits CR4[63:32] can only be used for IA-32e mode only
/// features that are enabled after entering 64-bit mode. Bits CR4[63:32] do not have any effect outside of IA-32e
/// mode.
pub const cr4 = packed struct(usize) {
    vme: bool = false,
    pvi: bool = false,
    timestamp_disable: bool = false,
    debugging_extensions: bool = false,
    page_size_extensions: bool = false,
    physical_address_extensions: bool = true,
    machine_check_enable: bool = false,
    page_global_enable: bool = true,
    performance_monitoring_counter_enable: bool = true,
    operating_system_support_for_fx_save_restore: bool = true,
    operating_system_support_for_unmasked_simd_fp_exceptions: bool = false,
    user_mode_instruction: bool = false,
    linear_addresses_57_bit: bool = false,
    vmx_enable: bool = false,
    smx_enable: bool = false,
    fs_gs_base_enable: bool = false,
    pcid_enable: bool = false,
    os_xsave_enable: bool = false,
    key_locker_enable: bool = false,
    supervisor_mode_execution_prevention_enable: bool = false,
    supervisor_mode_access_prevention_enable: bool = false,
    protection_key_user_mode_enable: bool = false,
    control_flow_enforcement_technology: bool = false,
    protection_key_supervisor_mode_enable: bool = false,
    reserved: u40 = 0,

    pub fn read() cr4 {
        return asm volatile (
            \\mov %%cr4, %[result]
            : [result] "=r" (-> cr4),
        );
    }

    pub fn write(cr4_register: cr4) void {
        asm volatile (
            \\mov %[cr4], %%cr4
            :
            : [cr4] "r" (cr4_register),
        );
    }
};

/// Provides read and write access to the Task Priority Register (TPR). It specifies the priority threshold
/// value that operating systems use to control the priority class of external interrupts allowed to interrupt the
/// processor. This register is available only in 64-bit mode. However, interrupt filtering continues to apply in
/// compatibility mode.
pub const cr8 = SimpleR64(.cr8);

pub const RFLAGS = packed struct(u64) {
    CF: bool = false,
    reserved0: bool = false,
    PF: bool = false,
    reserved1: bool = false,
    AF: bool = false,
    reserved2: bool = false,
    ZF: bool = false,
    SF: bool = false,
    TF: bool = false,
    IF: bool = false,
    DF: bool = false,
    OF: bool = false,
    IOPL: u2 = 0,
    NT: bool = false,
    reserved3: bool = false,
    RF: bool = false,
    VM: bool = false,
    AC: bool = false,
    VIF: bool = false,
    VIP: bool = false,
    ID: bool = false,
    reserved4: u10 = 0,
    reserved5: u32 = 0,

    comptime {
        assert(@sizeOf(RFLAGS) == @sizeOf(u64));
        assert(@bitSizeOf(RFLAGS) == @bitSizeOf(u64));
    }

    pub inline fn read() RFLAGS {
        return asm volatile (
            \\pushfq
            \\pop %[flags]
            : [flags] "=r" (-> RFLAGS),
        );
    }
};

//pub const RFLAGS = struct {
//pub const Flags = Bitflag(false, u64, enum(u6) {
//CF = 0,
//PF = 2,
//AF = 4,
//ZF = 6,
//SF = 7,
//TF = 8,
//IF = 9,
//DF = 10,
//OF = 11,
//IOPL0 = 12,
//IOPL1 = 13,
//NT = 14,
//RF = 16,
//VM = 17,
//AC = 18,
//VIF = 19,
//VIP = 20,
//ID = 21,
//});

//pub inline fn read() Flags {
//return Flags{
//.bits = asm volatile (
//\\pushfq
//\\pop %[flags]
//: [flags] "=r" (-> u64),
//),
//};
//}
//};

pub const IA32_LSTAR = SimpleMSR(0xC0000082);
pub const IA32_FMASK = SimpleMSR(0xC0000084);
pub const IA32_FS_BASE = SimpleMSR(0xC0000100);
pub const IA32_GS_BASE = SimpleMSR(0xC0000101);
pub const IA32_KERNEL_GS_BASE = SimpleMSR(0xC0000102);

pub const MemoryType = enum(u8) {
    uncacheable = 0,
    write_combining = 1,
    reserved0 = 2,
    reserved1 = 3,
    write_through = 4,
    write_protected = 5,
    write_back = 6,
    uncached = 7,
};

pub const IA32_PAT = extern struct {
    page_attributes: [8]MemoryType,

    const MSR = SimpleMSR(0x277);

    pub fn read() IA32_PAT {
        return @bitCast(IA32_PAT, MSR.read());
    }

    pub fn write(pat: IA32_PAT) void {
        MSR.write(@bitCast(u64, pat));
    }
};

pub const IA32_EFER = packed struct(u64) {
    /// Syscall Enable - syscall, sysret
    SCE: bool = false,
    reserved0: u7 = 0,
    /// Long Mode Enable
    LME: bool = false,
    reserved1: bool = false,
    /// Long Mode Active
    LMA: bool = false,
    /// Enables page access restriction by preventing instruction fetches from PAE pages with the XD bit set
    NXE: bool = false,
    SVME: bool = false,
    LMSLE: bool = false,
    FFXSR: bool = false,
    TCE: bool = false,
    reserved2: u48 = 0,

    comptime {
        assert(@sizeOf(u64) == @sizeOf(IA32_EFER));
    }

    pub const MSR = SimpleMSR(0xC0000080);

    pub fn read() IA32_EFER {
        const result = MSR.read();
        const typed_result = @bitCast(IA32_EFER, result);
        return typed_result;
    }

    pub fn write(typed_value: IA32_EFER) void {
        const value = @bitCast(u64, typed_value);
        MSR.write(value);
    }
};

pub const IA32_STAR = packed struct(u64) {
    reserved: u32 = 0,
    kernel_cs: u16 = 0,
    user_cs_anchor: u16 = 0,

    pub const MSR = SimpleMSR(0xC0000081);

    pub fn read() @This() {
        const result = MSR.read();
        const typed_result = @bitCast(@This(), result);
        return typed_result;
    }

    pub fn write(typed_value: @This()) void {
        const value = @bitCast(u64, typed_value);
        MSR.write(value);
    }
};

pub const IA32_APIC_BASE = packed struct(u64) {
    reserved0: u8 = 0,
    bsp: bool = false,
    reserved1: u1 = 0,
    extended: bool = false,
    global_enable: bool = false,
    address: u24,
    reserved2: u28 = 0,

    pub const MSR = SimpleMSR(0x0000001B);

    pub fn read() IA32_APIC_BASE {
        const result = MSR.read();
        const typed_result = @bitCast(IA32_APIC_BASE, result);
        return typed_result;
    }

    pub fn write(typed_value: IA32_APIC_BASE) void {
        const value = @bitCast(u64, typed_value);
        MSR.write(value);
    }

    pub fn get_address(ia32_apic_base: IA32_APIC_BASE) PhysicalAddress {
        return PhysicalAddress.new(@as(u64, ia32_apic_base.address) << @bitOffsetOf(IA32_APIC_BASE, "address"));
    }
};

pub fn get_apic_base() PhysicalAddress {
    return PhysicalAddress.new(@bitCast(u64, IA32_APIC_BASE.read()) & 0x0000_ffff_ffff_f000);
}

pub fn SimpleR64(comptime Register: SimpleRegister) type {
    return struct {
        pub inline fn read() u64 {
            return switch (Register) {
                .rax => asm volatile ("mov %%rax, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .rbx => asm volatile ("mov %%rbx, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .rcx => asm volatile ("mov %%rcx, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .rdx => asm volatile ("mov %%rdx, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .rbp => asm volatile ("mov %%rbp, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .rsp => asm volatile ("mov %%rsp, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .rsi => asm volatile ("mov %%rsi, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .rdi => asm volatile ("mov %%rdi, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .r8 => asm volatile ("mov %%r8, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .r9 => asm volatile ("mov %%r9, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .r10 => asm volatile ("mov %%r10, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .r11 => asm volatile ("mov %%r11, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .r12 => asm volatile ("mov %%r12, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .r13 => asm volatile ("mov %%r13, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .r14 => asm volatile ("mov %%r14, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .r15 => asm volatile ("mov %%r15, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .gs => asm volatile ("mov %%gs, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .cs => asm volatile ("mov %%cs, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .dr0 => asm volatile ("mov %%dr0, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .dr1 => asm volatile ("mov %%dr1, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .dr2 => asm volatile ("mov %%dr2, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .dr3 => asm volatile ("mov %%dr3, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .dr4 => asm volatile ("mov %%dr4, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .dr5 => asm volatile ("mov %%dr5, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .dr6 => asm volatile ("mov %%dr6, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .dr7 => asm volatile ("mov %%dr7, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .cr2 => asm volatile ("mov %%cr2, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .cr8 => asm volatile ("mov %%cr8, %[result]"
                    : [result] "=r" (-> u64),
                ),
            };
        }

        pub inline fn write(value: u64) void {
            switch (Register) {
                .rax => asm volatile ("mov %[in], %%rax"
                    :
                    : [in] "r" (value),
                ),
                .rbx => asm volatile ("mov %[in], %%rbx"
                    :
                    : [in] "r" (value),
                ),
                .rcx => asm volatile ("mov %[in], %%rcx"
                    :
                    : [in] "r" (value),
                ),
                .rdx => asm volatile ("mov %[in], %%rdx"
                    :
                    : [in] "r" (value),
                ),
                .rbp => asm volatile ("mov %[in], %%rbp"
                    :
                    : [in] "r" (value),
                ),
                .rsp => asm volatile ("mov %[in], %%rsp"
                    :
                    : [in] "r" (value),
                ),
                .rsi => asm volatile ("mov %[in], %%rsi"
                    :
                    : [in] "r" (value),
                ),
                .rdi => asm volatile ("mov %[in], %%rdi"
                    :
                    : [in] "r" (value),
                ),
                .r8 => asm volatile ("mov %[in], %%r8"
                    :
                    : [in] "r" (value),
                ),
                .r9 => asm volatile ("mov %[in], %%r9"
                    :
                    : [in] "r" (value),
                ),
                .r10 => asm volatile ("mov %[in], %%r10"
                    :
                    : [in] "r" (value),
                ),
                .r11 => asm volatile ("mov %[in], %%r11"
                    :
                    : [in] "r" (value),
                ),
                .r12 => asm volatile ("mov %[in], %%r12"
                    :
                    : [in] "r" (value),
                ),
                .r13 => asm volatile ("mov %[in], %%r13"
                    :
                    : [in] "r" (value),
                ),
                .r14 => asm volatile ("mov %[in], %%r14"
                    :
                    : [in] "r" (value),
                ),
                .r15 => asm volatile ("mov %[in], %%r15"
                    :
                    : [in] "r" (value),
                ),
                .gs => asm volatile ("mov %[in], %%gs"
                    :
                    : [in] "r" (value),
                ),
                .cs => asm volatile ("mov %[in], %%cs"
                    :
                    : [in] "r" (value),
                ),
                .dr0 => asm volatile ("mov %[in], %%dr0"
                    :
                    : [in] "r" (value),
                ),
                .dr1 => asm volatile ("mov %[in], %%dr1"
                    :
                    : [in] "r" (value),
                ),
                .dr2 => asm volatile ("mov %[in], %%dr2"
                    :
                    : [in] "r" (value),
                ),
                .dr3 => asm volatile ("mov %[in], %%dr3"
                    :
                    : [in] "r" (value),
                ),
                .dr4 => asm volatile ("mov %[in], %%dr4"
                    :
                    : [in] "r" (value),
                ),
                .dr5 => asm volatile ("mov %[in], %%dr5"
                    :
                    : [in] "r" (value),
                ),
                .dr6 => asm volatile ("mov %[in], %%dr6"
                    :
                    : [in] "r" (value),
                ),
                .dr7 => asm volatile ("mov %[in], %%dr7"
                    :
                    : [in] "r" (value),
                ),
                .cr2 => asm volatile ("mov %[in], %%cr2"
                    :
                    : [in] "r" (value),
                ),
                .cr8 => asm volatile ("mov %[in], %%cr8"
                    :
                    : [in] "r" (value),
                ),
            }
        }
    };
}

pub fn SimpleMSR(comptime msr: u32) type {
    return struct {
        pub inline fn read() u64 {
            var low: u32 = undefined;
            var high: u32 = undefined;

            asm volatile ("rdmsr"
                : [_] "={eax}" (low),
                  [_] "={edx}" (high),
                : [_] "{ecx}" (msr),
            );
            return (@as(u64, high) << 32) | low;
        }

        pub inline fn write(value: u64) void {
            const low = @truncate(u32, value);
            const high = @truncate(u32, value >> 32);

            asm volatile ("wrmsr"
                :
                : [_] "{eax}" (low),
                  [_] "{edx}" (high),
                  [_] "{ecx}" (msr),
            );
        }
    };
}

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
