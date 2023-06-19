const lib = @import("lib");
const assert = lib.assert;
const SimpleR64 = lib.arch.x86_64.registers.SimpleR64;
const RFLAGS = lib.arch.x86_64.registers.RFLAGS;

const privileged = @import("privileged");
const PhysicalAddress = lib.PhysicalAddress;
const VirtualAddress = lib.VirtualAddress;
const PhysicalMemoryRegion = lib.PhysicalMemoryRegion;
const VirtualMemoryRegion = lib.VirtualMemoryRegion;
const PhysicalAddressSpace = lib.PhysicalAddressSpace;

pub const cr3 = packed struct(u64) {
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
        assert(@sizeOf(cr3) == @sizeOf(u64));
        assert(@bitSizeOf(cr3) == @bitSizeOf(u64));
    }

    pub fn fromAddress(physical_address: PhysicalAddress) cr3 {
        const PackedAddressType = blk: {
            var foo_cr3: cr3 = undefined;
            break :blk @TypeOf(@field(foo_cr3, "address"));
        };

        return .{
            .address = @as(PackedAddressType, @intCast(physical_address.value() >> @bitOffsetOf(cr3, "address"))),
        };
    }

    pub inline fn read() cr3 {
        return asm volatile ("mov %cr3, %[result]"
            : [result] "=r" (-> cr3),
        );
    }

    pub inline fn write(value: cr3) void {
        asm volatile ("mov %[in], %cr3"
            :
            : [in] "r" (value),
        );
    }

    pub inline fn equal(self: cr3, other: cr3) bool {
        const self_int = @as(usize, @bitCast(self));
        const other_int = @as(usize, @bitCast(other));
        return self_int == other_int;
    }

    pub inline fn getAddress(self: cr3) PhysicalAddress {
        return PhysicalAddress.new(@as(u64, self.address) << @bitOffsetOf(cr3, "address"));
    }
};

/// Contains system control flags that control operating mode and states of the processor.
pub const cr0 = packed struct(u64) {
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
        return asm volatile ("mov %cr0, %[result]"
            : [result] "=r" (-> cr0),
        );
    }

    pub inline fn write(cr0r: cr0) void {
        asm volatile (
            \\mov %[cr0], %cr0
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
pub const cr4 = packed struct(u64) {
    vme: bool = false,
    pvi: bool = false,
    timestamp_disable: bool = false,
    debugging_extensions: bool = false,
    page_size_extensions: bool = false,
    physical_address_extensions: bool = true,
    machine_check_enable: bool = false,
    page_global_enable: bool = true,
    performance_monitoring_counter_enable: bool = true,
    OSFXSR: bool = true,
    OSXMMEXCPT: bool = false,
    user_mode_instruction: bool = false,
    linear_addresses_57_bit: bool = false,
    vmx_enable: bool = false,
    smx_enable: bool = false,
    fs_gs_base_enable: bool = false,
    pcid_enable: bool = false,
    OSXSAVE: bool = false,
    key_locker_enable: bool = false,
    supervisor_mode_execution_prevention_enable: bool = false,
    supervisor_mode_access_prevention_enable: bool = false,
    protection_key_user_mode_enable: bool = false,
    control_flow_enforcement_technology: bool = false,
    protection_key_supervisor_mode_enable: bool = false,
    reserved: u40 = 0,

    pub fn read() cr4 {
        return asm volatile (
            \\mov %cr4, %[result]
            : [result] "=r" (-> cr4),
        );
    }

    pub fn write(cr4_register: cr4) void {
        asm volatile (
            \\mov %[cr4], %cr4
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

pub const IA32_LSTAR = SimpleMSR(0xC0000082);
pub const IA32_FMASK = SimpleMSR(0xC0000084);
pub const syscall_mask = (1 << @bitOffsetOf(RFLAGS, "CF")) |
    (1 << @bitOffsetOf(RFLAGS, "PF")) |
    (1 << @bitOffsetOf(RFLAGS, "AF")) |
    (1 << @bitOffsetOf(RFLAGS, "ZF")) |
    (1 << @bitOffsetOf(RFLAGS, "SF")) |
    (1 << @bitOffsetOf(RFLAGS, "TF")) |
    (1 << @bitOffsetOf(RFLAGS, "IF")) |
    (1 << @bitOffsetOf(RFLAGS, "DF")) |
    (1 << @bitOffsetOf(RFLAGS, "OF")) |
    (1 << @bitOffsetOf(RFLAGS, "IOPL")) |
    (1 << @bitOffsetOf(RFLAGS, "NT")) |
    (1 << @bitOffsetOf(RFLAGS, "RF")) |
    (1 << @bitOffsetOf(RFLAGS, "AC")) |
    (1 << @bitOffsetOf(RFLAGS, "ID"));

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
            const low = @as(u32, @truncate(value));
            const high = @as(u32, @truncate(value >> 32));

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
        return @as(IA32_PAT, @bitCast(MSR.read()));
    }

    pub fn write(pat: IA32_PAT) void {
        MSR.write(@as(u64, @bitCast(pat)));
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
        const typed_result = @as(IA32_EFER, @bitCast(result));
        return typed_result;
    }

    pub fn write(typed_value: IA32_EFER) void {
        const value = @as(u64, @bitCast(typed_value));
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
        const typed_result = @as(@This(), @bitCast(result));
        return typed_result;
    }

    pub fn write(typed_value: @This()) void {
        const value = @as(u64, @bitCast(typed_value));
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

    pub inline fn read() IA32_APIC_BASE {
        const result = MSR.read();
        const typed_result = @as(IA32_APIC_BASE, @bitCast(result));
        return typed_result;
    }

    pub inline fn write(typed_value: IA32_APIC_BASE) void {
        const value = @as(u64, @bitCast(typed_value));
        MSR.write(value);
    }

    pub inline fn getAddress(ia32_apic_base: IA32_APIC_BASE) PhysicalAddress {
        return PhysicalAddress.new(@as(u64, ia32_apic_base.address) << @bitOffsetOf(IA32_APIC_BASE, "address"));
    }
};

pub const XCR0 = packed struct(u64) {
    X87: bool = true,
    SSE: bool = true,
    AVX: bool = false,
    BNDREG: bool = false,
    BNDCSR: bool = false,
    opmask: bool = false,
    ZMM_hi256: bool = false,
    Hi16_ZMM: bool = false,
    _: bool = false,
    PKRU: bool = false,
    reserved: u7 = 0,
    AMX_TILECFG: bool = false,
    AMX_TILEDATA: bool = false,
    reserved1: u45 = 0,

    pub inline fn read() XCR0 {
        var eax: u32 = undefined;
        var edx: u32 = undefined;

        asm volatile (
            \\xgetbv
            : [eax] "={eax}" (eax),
              [edx] "={edx}" (edx),
            : [ecx] "i" (@as(u32, 0)),
        );

        const xcr0 = @as(XCR0, @bitCast(@as(u64, edx) << 32 | eax));
        return xcr0;
    }

    pub inline fn write(xcr0: XCR0) void {
        const bitcasted_xcr0 = @as(u64, @bitCast(xcr0));
        const eax = @as(u32, @truncate(bitcasted_xcr0));
        const edx = @as(u32, @truncate(bitcasted_xcr0 >> 32));

        asm volatile (
            \\xsetbv
            :
            : [eax] "{eax}" (eax),
              [edx] "{edx}" (edx),
              [ecx] "{edx}" (@as(u32, 0)),
        );
    }
};

pub const FSBASE = struct {
    pub inline fn write(value: u64) void {
        asm volatile (
            \\wrfsbase
            :
            : [value] "r" (value),
        );
    }

    pub inline fn read() u64 {
        return asm volatile (
            \\wrfsbase
            : [value] "r" (-> u64),
        );
    }
};
