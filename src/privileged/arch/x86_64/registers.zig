const common = @import("common");
const assert = common.assert;
const SimpleR64 = common.arch.x86_64.registers.SimpleR64;

const privileged = @import("privileged");
const PhysicalAddress = privileged.PhysicalAddress;

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

    pub fn from_address(physical_address: PhysicalAddress(.local)) cr3 {
        const PackedAddressType = blk: {
            var foo_cr3: cr3 = undefined;
            break :blk @TypeOf(@field(foo_cr3, "address"));
        };

        return .{
            .address = @intCast(PackedAddressType, physical_address.value() >> @bitOffsetOf(cr3, "address")),
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

    pub inline fn get_address(self: cr3) PhysicalAddress(.local) {
        return PhysicalAddress(.local).new(@as(usize, self.address) << @bitOffsetOf(cr3, "address"));
    }
};

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

pub const IA32_LSTAR = SimpleMSR(0xC0000082);
pub const IA32_FMASK = SimpleMSR(0xC0000084);
pub const IA32_FS_BASE = SimpleMSR(0xC0000100);
pub const IA32_GS_BASE = SimpleMSR(0xC0000101);
pub const IA32_KERNEL_GS_BASE = SimpleMSR(0xC0000102);

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

    pub fn get_address(ia32_apic_base: IA32_APIC_BASE) PhysicalAddress(.global) {
        return PhysicalAddress(.global).new(@as(u64, ia32_apic_base.address) << @bitOffsetOf(IA32_APIC_BASE, "address"));
    }
};
