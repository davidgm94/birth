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
const cr0 = packed struct(usize) {
    protected_mode_enable: bool = true,
    monitor_coprocessor: bool = false,
    emulation: bool = false,
    task_switched: bool = false,
    extension_type: bool = false,
    numeric_error: bool = false,
    write_protect: bool = true,
    alignment_mask: bool = false,
    not_write_through: bool = false,
    cache_disable: bool = false,
    paging: bool = true,
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
pub const cr4 = packed struct (usize) {
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



    /// Performance-Monitoring Counter Enable (bit 8 of CR4) — Enables execution of the RDPMC instruc-
    /// tion for programs or procedures running at any protection level when set; RDPMC instruction can be
    /// executed only at protection level 0 when clear.
    PME = 8,

    /// Operating System Support for FXSAVE and FXRSTOR instructions (bit 9 of CR4) — When set, this
    /// flag: (1) indicates to software that the operating system supports the use of the FXSAVE and FXRSTOR
    /// instructions, (2) enables the FXSAVE and FXRSTOR instructions to save and restore the contents of the
    /// XMM and MXCSR registers along with the contents of the x87 FPU and MMX registers, and (3) enables the
    /// processor to execute SSE/SSE2/SSE3/SSSE3/SSE4 instructions, with the exception of the PAUSE,
    /// PREFETCHh, SFENCE, LFENCE, MFENCE, MOVNTI, CLFLUSH, CRC32, and POPCNT.
    /// If this flag is clear, the FXSAVE and FXRSTOR instructions will save and restore the contents of the x87 FPU
    /// and MMX registers, but they may not save and restore the contents of the XMM and MXCSR registers. Also,
    /// the processor will generate an invalid opcode exception (#UD) if it attempts to execute any
    /// SSE/SSE2/SSE3 instruction, with the exception of PAUSE, PREFETCHh, SFENCE, LFENCE, MFENCE,
    /// MOVNTI, CLFLUSH, CRC32, and POPCNT. The operating system or executive must explicitly set this flag.
    /// NOTE
    /// CPUID feature flag FXSR indicates availability of the FXSAVE/FXRSTOR instructions. The OSFXSR
    /// bit provides operating system software with a means of enabling FXSAVE/FXRSTOR to save/restore
    /// the contents of the X87 FPU, XMM and MXCSR registers. Consequently OSFXSR bit indicates that
    /// the operating system provides context switch support for SSE/SSE2/SSE3/SSSE3/SSE4.
    OSFXSR = 9,

    /// Operating System Support for Unmasked SIMD Floating-Point Exceptions (bit 10 of CR4) —
    /// When set, indicates that the operating system supports the handling of unmasked SIMD floating-point
    /// exceptions through an exception handler that is invoked when a SIMD floating-point exception (#XM) is
    /// generated. SIMD floating-point exceptions are only generated by SSE/SSE2/SSE3/SSE4.1 SIMD floating-
    /// point instructions.
    /// The operating system or executive must explicitly set this flag. If this flag is not set, the processor will
    /// generate an invalid opcode exception (#UD) whenever it detects an unmasked SIMD floating-point excep-
    /// tion.
    OSXMMEXCPT = 10,

    /// User-Mode Instruction Prevention (bit 11 of CR4) — When set, the following instructions cannot be
    /// executed if CPL > 0: SGDT, SIDT, SLDT, SMSW, and STR. An attempt at such execution causes a general-
    /// protection exception (#GP).
    UMIP = 11,

    /// 57-bit linear addresses (bit 12 of CR4) — When set in IA-32e mode, the processor uses 5-level paging
    /// to translate 57-bit linear addresses. When clear in IA-32e mode, the processor uses 4-level paging to
    /// translate 48-bit linear addresses. This bit cannot be modified in IA-32e mode.
    LA57 = 12,

    /// VMX-Enable Bit (bit 13 of CR4) — Enables VMX operation when set. See Chapter 23, “Introduction to
    /// Virtual Machine Extensions.”
    VMXE = 13,

    /// SMX-Enable Bit (bit 14 of CR4) — Enables SMX operation when set. See Chapter 6, “Safer Mode Exten-
    /// sions Reference” of Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 2D.
    SMXE = 14,

    /// FSGSBASE-Enable Bit (bit 16 of CR4) — Enables the instructions RDFSBASE, RDGSBASE, WRFSBASE,
    /// and WRGSBASE.
    FSGSBASE = 16,

    /// PCID-Enable Bit (bit 17 of CR4) — Enables process-context identifiers (PCIDs) when set. See Section
    /// 4.10.1, “Process-Context Identifiers (PCIDs)”. Applies only in IA-32e mode (if IA32_EFER.LMA = 1).
    PCIDE = 17,

    /// XSAVE and Processor Extended States-Enable Bit (bit 18 of CR4) — When set, this flag: (1) indi-
    /// cates (via CPUID.01H:ECX.OSXSAVE[bit 27]) that the operating system supports the use of the XGETBV,
    /// XSAVE and XRSTOR instructions by general software; (2) enables the XSAVE and XRSTOR instructions to
    /// save and restore the x87 FPU state (including MMX registers), the SSE state (XMM registers and MXCSR),
    /// along with other processor extended states enabled in XCR0; (3) enables the processor to execute XGETBV
    /// and XSETBV instructions in order to read and write XCR0. See Section 2.6 and Chapter 13, “System
    /// Programming for Instruction Set Extensions and Processor Extended States”.
    OSXSAVE = 18,

    /// Key-Locker-Enable Bit (bit 19 of CR4) — When set, the LOADIWKEY instruction is enabled; in addition,
    /// if support for the AES Key Locker instructions has been activated by system firmware,
    /// CPUID.19H:EBX.AESKLE[bit 0] is enumerated as 1 and the AES Key Locker instructions are enabled.1
    /// When clear, CPUID.19H:EBX.AESKLE[bit 0] is enumerated as 0 and execution of any Key Locker instruction
    /// causes an invalid-opcode exception (#UD).
    KL = 19,

    /// SMEP-Enable Bit (bit 20 of CR4) — Enables supervisor-mode execution prevention (SMEP) when set.
    /// See Section 4.6, “Access Rights”.
    SMEP = 20,

    /// SMAP-Enable Bit (bit 21 of CR4) — Enables supervisor-mode access prevention (SMAP) when set. See
    /// Section 4.6, “Access Rights.”
    SMAP = 21,

    /// Enable protection keys for user-mode pages (bit 22 of CR4) — 4-level paging and 5-level paging
    /// associate each user-mode linear address with a protection key. When set, this flag indicates (via
    /// CPUID.(EAX=07H,ECX=0H):ECX.OSPKE [bit 4]) that the operating system supports use of the PKRU
    /// register to specify, for each protection key, whether user-mode linear addresses with that protection key
    /// can be read or written. This bit also enables access to the PKRU register using the RDPKRU and WRPKRU
    /// instructions.
    PKE = 22,

    /// Control-flow Enforcement Technology (bit 23 of CR4) — Enables control-flow enforcement tech-
    /// nology when set. See Chapter 18, “Control-flow Enforcement Technology (CET)” of the IA-32 Intel® Archi-
    /// tecture Software Developer’s Manual, Volume 1. This flag can be set only if CR0.WP is set, and it must be
    /// clear before CR0.WP can be cleared (see below).
    CET = 23,

    /// Enable protection keys for supervisor-mode pages (bit 24 of CR4) — 4-level paging and 5-level
    /// paging associate each supervisor-mode linear address with a protection key. When set, this flag allows use
    /// of the IA32_PKRS MSR to specify, for each protection key, whether supervisor-mode linear addresses with
    /// that protection key can be read or written.
    PKS = 24,
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

pub fn ComplexR64(comptime Register: ComplexRegister, comptime _BitEnum: type) type {
    return struct {
        const BitEnum = _BitEnum;
        pub inline fn read_raw() u64 {
            return switch (Register) {
                .cr0 => asm volatile ("mov %%cr0, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .cr3 => asm volatile ("mov %%cr3, %[result]"
                    : [result] "=r" (-> u64),
                ),
                .cr4 => asm volatile ("mov %%cr4, %[result]"
                    : [result] "=r" (-> u64),
                ),
            };
        }

        pub inline fn write_raw(value: u64) void {
            switch (Register) {
                .cr0 => asm volatile ("mov %[in], %%cr0"
                    :
                    : [in] "r" (value),
                ),
                .cr3 => asm volatile ("mov %[in], %%cr3"
                    :
                    : [in] "r" (value),
                ),
                .cr4 => asm volatile ("mov %[in], %%cr4"
                    :
                    : [in] "r" (value),
                ),
            }
        }

        pub inline fn read() Value {
            return Value{
                .value = read_raw(),
            };
        }

        pub inline fn write(value: Value) void {
            write_raw(value.value);
        }

        pub inline fn get_bit(comptime bit: BitEnum) bool {
            return read().get_bit(bit);
        }

        pub inline fn set_bit(comptime bit: BitEnum) void {
            var value = read();
            value.set_bit(bit);
            write(value);
        }

        pub inline fn clear_bit(comptime bit: BitEnum) void {
            var value = read();
            value.clear_bit(bit);
            write(value);
        }

        pub const Value = struct {
            value: u64,

            pub inline fn get_bit(value: Value, comptime bit: BitEnum) bool {
                return value.value & (1 << @enumToInt(bit)) != 0;
            }

            pub inline fn set_bit(value: *Value, comptime bit: BitEnum) void {
                value.value |= 1 << @enumToInt(bit);
            }

            pub inline fn clear_bit(value: *Value, comptime bit: BitEnum) void {
                const mask = ~(1 << @enumToInt(bit));
                value.value &= mask;
            }
        };
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
