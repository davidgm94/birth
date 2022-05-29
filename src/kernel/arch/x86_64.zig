const kernel = @import("../kernel.zig");
const TODO = kernel.TODO;

const log = kernel.log.scoped(.x86_64);

pub const page_size = 0x1000;

pub const Stivale2 = @import("x86_64/limine/stivale2/stivale2.zig");
pub const Spinlock = @import("x86_64/spinlock.zig");
pub const PIC = @import("x86_64/pic.zig");
pub const interrupts = @import("x86_64/interrupts.zig");

pub export fn start(stivale_struct: *Stivale2.Struct) noreturn {
    interrupts.disable();
    log.debug("Hello kernel!", .{});
    const memory_map_struct = Stivale2.find(Stivale2.Struct.MemoryMap, stivale_struct) orelse @panic("Stivale had no memory map struct");
    const rsdp_struct = Stivale2.find(Stivale2.Struct.RSDP, stivale_struct) orelse @panic("Stivale had no RSDP struct");
    const framebuffer_struct = Stivale2.find(Stivale2.Struct.Framebuffer, stivale_struct) orelse @panic("Stivale had no framebuffer struct");
    const kernel_struct = Stivale2.find(Stivale2.Struct.KernelFileV2, stivale_struct) orelse @panic("Stivale had no kernel struct");
    const modules_struct = Stivale2.find(Stivale2.Struct.Modules, stivale_struct) orelse @panic("Stivale had no modules struct");
    const epoch_struct = Stivale2.find(Stivale2.Struct.Epoch, stivale_struct) orelse @panic("Stivale had no epoch struct");
    _ = memory_map_struct;
    _ = rsdp_struct;
    _ = framebuffer_struct;
    _ = kernel_struct;
    _ = modules_struct;
    _ = epoch_struct;

    enable_cpu_features();

    interrupts.init();

    const memory_map = Stivale2.process_memory_map(memory_map_struct);
    for (memory_map) |map_entry| {
        log.debug("(0x{x}, {}, {})", .{ map_entry.region.address, map_entry.region.size, map_entry.type });
    }

    while (true) {
        kernel.spinloop_hint();
    }
}

pub const IOPort = struct {
    pub const DMA1 = 0x0000;
    pub const PIC1 = 0x0020;
    pub const Cyrix_MSR = 0x0022;
    pub const PIT = 0x0040;
    pub const PS2 = 0x0060;
    pub const CMOS_RTC = 0x0070;
    pub const DMA_page_registers = 0x0080;
    pub const A20 = 0x0092;
    pub const PIC2 = 0x00a0;
    pub const DMA2 = 0x00c0;
    pub const E9_hack = 0x00e9;
    pub const ATA2 = 0x0170;
    pub const ATA1 = 0x01f0;
    pub const parallel_port = 0x0278;
    pub const serial2 = 0x02f8;
    pub const IBM_VGA = 0x03b0;
    pub const floppy = 0x03f0;
    pub const serial1 = 0x03f8;
};

const Serial = struct {
    const io_ports = [8]u16{
        0x3F8,
        0x2F8,
        0x3E8,
        0x2E8,
        0x5F8,
        0x4F8,
        0x5E8,
        0x4E8,
    };

    var initialization_state = [1]bool{false} ** 8;

    const InitError = error{
        already_initialized,
        not_present,
    };

    fn Port(comptime port_number: u8) type {
        comptime kernel.assert_unsafe(@src(), port_number > 0 and port_number <= 8);
        const port_index = port_number - 1;

        return struct {
            const io_port = io_ports[port_index];

            fn init() Serial.InitError!void {
                if (initialization_state[port_index]) return Serial.InitError.already_initialized;

                out8(io_port + 7, 0);
                if (in8(io_port + 7) != 0) return Serial.InitError.not_present;
                out8(io_port + 7, 0xff);
                if (in8(io_port + 7) != 0xff) return Serial.InitError.not_present;
                TODO();
            }
        };
    }
};

pub inline fn out8(comptime port: u16, value: u8) void {
    asm volatile ("outb %[value], %[port]"
        :
        : [value] "{al}" (value),
          [port] "N{dx}" (port),
    );
}

pub inline fn in8(comptime port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (port),
    );
}

pub inline fn writer_function(str: []const u8) usize {
    for (str) |c| {
        out8(IOPort.E9_hack, c);
    }

    return str.len;
}

pub const rax = SimpleR64("rax");
pub const rbx = SimpleR64("rbx");
pub const rcx = SimpleR64("rcx");
pub const rdx = SimpleR64("rdx");
pub const rbp = SimpleR64("rbp");
pub const rsp = SimpleR64("rsp");
pub const rsi = SimpleR64("rsi");
pub const rdi = SimpleR64("rdi");
pub const r8 = SimpleR64("r8");
pub const r9 = SimpleR64("r9");
pub const r10 = SimpleR64("r10");
pub const r11 = SimpleR64("r11");
pub const r12 = SimpleR64("r12");
pub const r13 = SimpleR64("r13");
pub const r14 = SimpleR64("r14");
pub const r15 = SimpleR64("r15");

pub fn SimpleR64(comptime name: []const u8) type {
    return struct {
        pub inline fn read() u64 {
            return asm volatile ("mov %%" ++ name ++ ", %[result]"
                : [result] "={rax}" (-> u64),
            );
        }

        pub inline fn write(value: u64) void {
            asm volatile ("mov %[in], %%" ++ name
                :
                : [in] "r" (value),
            );
        }
    };
}

pub fn ComplexR64(comptime name: []const u8, comptime _BitEnum: type) type {
    return struct {
        const BitEnum = _BitEnum;
        pub inline fn read_raw() u64 {
            return asm volatile ("mov %%" ++ name ++ ", %[result]"
                : [result] "={rax}" (-> u64),
            );
        }

        pub inline fn write_raw(value: u64) void {
            asm volatile ("mov %[in], %%" ++ name
                :
                : [in] "r" (value),
            );
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

// From Intel manual, volume 3, chapter 2.5: Control Registers

/// Contains system control flags that control operating mode and states of the processor.
const cr0 = ComplexR64("cr0", enum(u6) {
    /// Protection Enable (bit 0 of CR0) — Enables protected mode when set; enables real-address mode when
    /// clear. This flag does not enable paging directly. It only enables segment-level protection. To enable paging,
    /// both the PE and PG flags must be set.
    /// See also: Section 9.9, “Mode Switching.”
    PE = 0,

    /// Monitor Coprocessor (bit 1 of CR0) — Controls the interaction of the WAIT (or FWAIT) instruction with
    /// the TS flag (bit 3 of CR0). If the MP flag is set, a WAIT instruction generates a device-not-available exception
    /// (#NM) if the TS flag is also set. If the MP flag is clear, the WAIT instruction ignores the setting of the TS flag.
    /// Table 9-3 shows the recommended setting of this flag, depending on the IA-32 processor and x87 FPU or
    /// math coprocessor present in the system. Table 2-2 shows the interaction of the MP, EM, and TS flags.
    MP = 1,

    /// Emulation (bit 2 of CR0) — Indicates that the processor does not have an internal or external x87 FPU when set;
    /// indicates an x87 FPU is present when clear. This flag also affects the execution of
    /// MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instructions.
    /// When the EM flag is set, execution of an x87 FPU instruction generates a device-not-available exception
    /// (#NM). This flag must be set when the processor does not have an internal x87 FPU or is not connected to
    /// an external math coprocessor. Setting this flag forces all floating-point instructions to be handled by soft-
    /// ware emulation. Table 9-3 shows the recommended setting of this flag, depending on the IA-32 processor
    /// and x87 FPU or math coprocessor present in the system. Table 2-2 shows the interaction of the EM, MP, and
    /// TS flags.
    /// Also, when the EM flag is set, execution of an MMX instruction causes an invalid-opcode exception (#UD)
    /// to be generated (see Table 12-1). Thus, if an IA-32 or Intel 64 processor incorporates MMX technology, the
    /// EM flag must be set to 0 to enable execution of MMX instructions.
    /// Similarly for SSE/SSE2/SSE3/SSSE3/SSE4 extensions, when the EM flag is set, execution of most
    /// SSE/SSE2/SSE3/SSSE3/SSE4 instructions causes an invalid opcode exception (#UD) to be generated (see
    /// Table 13-1). If an IA-32 or Intel 64 processor incorporates the SSE/SSE2/SSE3/SSSE3/SSE4 extensions,
    /// the EM flag must be set to 0 to enable execution of these extensions. SSE/SSE2/SSE3/SSSE3/SSE4
    /// instructions not affected by the EM flag include: PAUSE, PREFETCHh, SFENCE, LFENCE, MFENCE, MOVNTI,
    /// CLFLUSH, CRC32, and POPCNT.
    EM = 2,

    /// Task Switched (bit 3 of CR0) — Allows the saving of the x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4
    /// context on a task switch to be delayed until an x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction is
    /// actually executed by the new task. The processor sets this flag on every task switch and tests it when
    /// executing x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instructions.
    /// * If the TS flag is set and the EM flag (bit 2 of CR0) is clear, a device-not-available exception (#NM) is
    /// raised prior to the execution of any x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction; with the
    /// exception of PAUSE, PREFETCHh, SFENCE, LFENCE, MFENCE, MOVNTI, CLFLUSH, CRC32, and POPCNT.
    /// See the paragraph below for the special case of the WAIT/FWAIT instructions.
    /// * If the TS flag is set and the MP flag (bit 1 of CR0) and EM flag are clear, an #NM exception is not raised
    /// prior to the execution of an x87 FPU WAIT/FWAIT instruction.
    /// * If the EM flag is set, the setting of the TS flag has no effect on the execution of x87
    /// FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instructions.
    /// Table 2-2 shows the actions taken when the processor encounters an x87 FPU instruction based on the
    /// settings of the TS, EM, and MP flags. Table 12-1 and 13-1 show the actions taken when the processor
    /// encounters an MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction.
    /// The processor does not automatically save the context of the x87 FPU, XMM, and MXCSR registers on a
    /// task switch. Instead, it sets the TS flag, which causes the processor to raise an #NM exception whenever it
    /// encounters an x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction in the instruction stream for the
    /// new task (with the exception of the instructions listed above).
    /// The fault handler for the #NM exception can then be used to clear the TS flag (with the CLTS instruction)
    /// and save the context of the x87 FPU, XMM, and MXCSR registers. If the task never encounters an x87
    /// FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction, the x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4
    /// context is never saved.
    TS = 3,

    /// Extension Type (bit 4 of CR0) — Reserved in the Pentium 4, Intel Xeon, P6 family, and Pentium proces-
    /// sors. In the Pentium 4, Intel Xeon, and P6 family processors, this flag is hardcoded to 1. In the Intel386
    /// and Intel486 processors, this flag indicates support of Intel 387 DX math coprocessor instructions when
    /// set.
    ET = 4,

    /// Numeric Error (bit 5 of CR0) — Enables the native (internal) mechanism for reporting x87 FPU errors
    /// when set; enables the PC-style x87 FPU error reporting mechanism when clear. When the NE flag is clear
    /// and the IGNNE# input is asserted, x87 FPU errors are ignored. When the NE flag is clear and the IGNNE#
    /// input is deasserted, an unmasked x87 FPU error causes the processor to assert the FERR# pin to generate
    /// an external interrupt and to stop instruction execution immediately before executing the next waiting
    /// floating-point instruction or WAIT/FWAIT instruction.
    /// The FERR# pin is intended to drive an input to an external interrupt controller (the FERR# pin emulates the
    /// ERROR# pin of the Intel 287 and Intel 387 DX math coprocessors). The NE flag, IGNNE# pin, and FERR#
    /// pin are used with external logic to implement PC-style error reporting. Using FERR# and IGNNE# to handle
    /// floating-point exceptions is deprecated by modern operating systems; this non-native approach also limits
    /// newer processors to operate with one logical processor active.
    /// See also: Section 8.7, “Handling x87 FPU Exceptions in Software” in Chapter 8, “Programming with the x87
    /// FPU,” and Appendix A, “EFLAGS Cross-Reference,” in the Intel® 64 and IA-32 Architectures Software
    /// Developer’s Manual, Volume 1.
    NE = 5,

    /// Write Protect (bit 16 of CR0) — When set, inhibits supervisor-level procedures from writing into read-
    /// only pages; when clear, allows supervisor-level procedures to write into read-only pages (regardless of the
    /// U/S bit setting; see Section 4.1.3 and Section 4.6). This flag facilitates implementation of the copy-on-
    /// write method of creating a new process (forking) used by operating systems such as UNIX. This flag must
    /// be set before software can set CR4.CET, and it cannot be cleared as long as CR4.CET = 1 (see below).
    WP = 16,

    /// Alignment Mask (bit 18 of CR0) — Enables automatic alignment checking when set; disables alignment
    /// checking when clear. Alignment checking is performed only when the AM flag is set, the AC flag in the
    /// EFLAGS register is set, CPL is 3, and the processor is operating in either protected or virtual-8086 mode
    AM = 18,

    /// Not Write-through (bit 29 of CR0) — When the NW and CD flags are clear, write-back (for Pentium 4,
    /// Intel Xeon, P6 family, and Pentium processors) or write-through (for Intel486 processors) is enabled for
    /// writes that hit the cache and invalidation cycles are enabled. See Table 11-5 for detailed information about
    /// the effect of the NW flag on caching for other settings of the CD and NW flags.
    NW = 29,

    /// Cache Disable (bit 30 of CR0) — When the CD and NW flags are clear, caching of memory locations for
    /// the whole of physical memory in the processor’s internal (and external) caches is enabled. When the CD
    /// flag is set, caching is restricted as described in Table 11-5. To prevent the processor from accessing and
    /// updating its caches, the CD flag must be set and the caches must be invalidated so that no cache hits can
    /// occur.
    /// See also: Section 11.5.3, “Preventing Caching,” and Section 11.5, “Cache Control.”
    CD = 30,

    /// Paging (bit 31 of CR0) — Enables paging when set; disables paging when clear. When paging is
    /// disabled, all linear addresses are treated as physical addresses. The PG flag has no effect if the PE flag (bit
    /// 0 of register CR0) is not also set; setting the PG flag when the PE flag is clear causes a general-protection
    /// exception (#GP). See also: Chapter 4, “Paging.”
    /// On Intel 64 processors, enabling and disabling IA-32e mode operation also requires modifying CR0.PG.
    PG = 31,
});
// RESERVED: const CR1 = R64("cr1");

/// Contains the page-fault linear address (the linear address that caused a page fault).
const cr2 = SimpleR64("cr2");

/// Contains the physical address of the base of the paging-structure hierarchy and two flags (PCD and
/// PWT). Only the most-significant bits (less the lower 12 bits) of the base address are specified; the lower 12 bits
/// of the address are assumed to be 0. The first paging structure must thus be aligned to a page (4-KByte)
/// boundary. The PCD and PWT flags control caching of that paging structure in the processor’s internal data
/// caches (they do not control TLB caching of page-directory information).
/// When using the physical address extension, the CR3 register contains the base address of the page-directory-
/// pointer table. With 4-level paging and 5-level paging, the CR3 register contains the base address of the PML4
/// table and PML5 table, respectively. If PCIDs are enabled, CR3 has a format different from that illustrated in
/// Figure 2-7. See Section 4.5, “4-Level Paging and 5-Level Paging.”
/// See also: Chapter 4, “Paging.”
const cr3 = ComplexR64("cr3", enum(u6) {
    /// Page-level Write-Through (bit 3 of CR3) — Controls the memory type used to access the first paging
    /// structure of the current paging-structure hierarchy. See Section 4.9, “Paging and Memory Typing”. This bit
    /// is not used if paging is disabled, with PAE paging, or with 4-level paging or 5-level paging if CR4.PCIDE=1.
    PWT = 3,

    /// Page-level Cache Disable (bit 4 of CR3) — Controls the memory type used to access the first paging
    /// structure of the current paging-structure hierarchy. See Section 4.9, “Paging and Memory Typing”. This bit
    /// is not used if paging is disabled, with PAE paging, or with 4-level paging1 or 5-level paging if CR4.PCIDE=1.
    PCD = 4,

    PCID_top_bit = 11,
});

/// Contains a group of flags that enable several architectural extensions, and indicate operating system or
/// executive support for specific processor capabilities. Bits CR4[63:32] can only be used for IA-32e mode only
/// features that are enabled after entering 64-bit mode. Bits CR4[63:32] do not have any effect outside of IA-32e
/// mode.
const cr4 = ComplexR64("cr4", enum(u6) {
    /// Virtual-8086 Mode Extensions (bit 0 of CR4) — Enables interrupt- and exception-handling extensions
    /// in virtual-8086 mode when set; disables the extensions when clear. Use of the virtual mode extensions can
    /// improve the performance of virtual-8086 applications by eliminating the overhead of calling the virtual-
    /// 8086 monitor to handle interrupts and exceptions that occur while executing an 8086 program and,
    /// instead, redirecting the interrupts and exceptions back to the 8086 program’s handlers. It also provides
    /// hardware support for a virtual interrupt flag (VIF) to improve reliability of running 8086 programs in multi-
    /// tasking and multiple-processor environments.
    /// See also: Section 20.3, “Interrupt and Exception Handling in Virtual-8086 Mode.”
    VME = 0,

    /// Protected-Mode Virtual Interrupts (bit 1 of CR4) — Enables hardware support for a virtual interrupt
    /// flag (VIF) in protected mode when set; disables the VIF flag in protected mode when clear.
    /// See also: Section 20.4, “Protected-Mode Virtual Interrupts.”
    PVI = 1,

    /// Time Stamp Disable (bit 2 of CR4) — Restricts the execution of the RDTSC instruction to procedures
    /// running at privilege level 0 when set; allows RDTSC instruction to be executed at any privilege level when
    /// clear. This bit also applies to the RDTSCP instruction if supported (if CPUID.80000001H:EDX[27] = 1).
    TSD = 2,

    /// Debugging Extensions (bit 3 of CR4) — References to debug registers DR4 and DR5 cause an unde-
    /// fined opcode (#UD) exception to be generated when set; when clear, processor aliases references to regis-
    /// ters DR4 and DR5 for compatibility with software written to run on earlier IA-32 processors.
    /// See also: Section 17.2.2, “Debug Registers DR4 and DR5.”
    DE = 3,

    /// Page Size Extensions (bit 4 of CR4) — Enables 4-MByte pages with 32-bit paging when set; restricts
    /// 32-bit paging to pages of 4 KBytes when clear.
    /// See also: Section 4.3, “32-Bit Paging.”
    PSE = 4,

    /// Physical Address Extension (bit 5 of CR4) — When set, enables paging to produce physical addresses
    /// with more than 32 bits. When clear, restricts physical addresses to 32 bits. PAE must be set before entering
    /// IA-32e mode.
    /// See also: Chapter 4, “Paging.”
    PAE = 5,

    /// Machine-Check Enable (bit 6 of CR4) — Enables the machine-check exception when set; disables the
    /// machine-check exception when clear.
    /// See also: Chapter 15, “Machine-Check Architecture.”
    MCE = 6,

    /// Page Global Enable (bit 7 of CR4) — (Introduced in the P6 family processors.) Enables the global page
    /// feature when set; disables the global page feature when clear. The global page feature allows frequently
    /// used or shared pages to be marked as global to all users (done with the global flag, bit 8, in a page-direc-
    /// tory-pointer-table entry, a page-directory entry, or a page-table entry). Global pages are not flushed from
    /// the translation-lookaside buffer (TLB) on a task switch or a write to register CR3.
    /// When enabling the global page feature, paging must be enabled (by setting the PG flag in control register
    /// CR0) before the PGE flag is set. Reversing this sequence may affect program correctness, and processor
    /// performance will be impacted.
    /// See also: Section 4.10, “Caching Translation Information.”
    PGE = 7,

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
});

/// Provides read and write access to the Task Priority Register (TPR). It specifies the priority threshold
/// value that operating systems use to control the priority class of external interrupts allowed to interrupt the
/// processor. This register is available only in 64-bit mode. However, interrupt filtering continues to apply in
/// compatibility mode.
const cr8 = SimpleR64("cr8");
fn get_task_priority_level() u4 {
    return @truncate(u4, cr8.read());
}

fn enable_cpu_features() void {
    //set_cpu_local_storage(0);
    // Initialize FPU
    var cr0_value = cr0.read();
    cr0_value.set_bit(.MP);
    cr0_value.set_bit(.NE);
    cr0.write(cr0_value);
    var cr4_value = cr4.read();
    cr4_value.set_bit(.OSFXSR);
    cr4_value.set_bit(.OSXMMEXCPT);
    cr4.write(cr4_value);

    log.debug("@TODO: MXCSR. See Intel manual", .{});
    // @TODO: is this correct?
    const cw: u16 = 0x037a;
    asm volatile (
        \\fninit
        \\fldcw (%[cw])
        :
        : [cw] "r" (&cw),
    );

    log.debug("Making sure the cache is initialized properly", .{});
    kernel.assert(@src(), !cr0.get_bit(.CD));
    kernel.assert(@src(), !cr0.get_bit(.NW));
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

pub fn ComplexMSR(comptime msr: u32, comptime _BitEnum: type) type {
    return struct {
        pub const BitEnum = _BitEnum;
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

pub const PAT = SimpleMSR(0x277);
pub const EFER = ComplexMSR(0xC0000080, enum(u6) {
    /// Syscall Enable - syscall, sysret
    SCE = 0,
    /// Long Mode Enable
    LME = 8,
    /// Long Mode Active
    LMA = 10,
    /// Enables page access restriction by preventing instruction fetches from PAE pages with the XD bit set
    NXE = 11,
    SVME = 12,
    LMSLE = 13,
    FFXSR = 14,
    TCE = 15,
});
pub const GS_base = SimpleMSR(0xc0000102);

pub const CPUID = struct {
    eax: u32,
    ebx: u32,
    edx: u32,
    ecx: u32,

    /// Returns the maximum number bits a physical address is allowed to have in this CPU
    pub inline fn get_max_physical_address() u6 {
        return @truncate(u6, cpuid(0x80000008).eax);
    }
};

pub inline fn cpuid(leaf: u32) CPUID {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var edx: u32 = undefined;
    var ecx: u32 = undefined;

    asm volatile (
        \\cpuid
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [edx] "={edx}" (edx),
          [ecx] "={ecx}" (ecx),
        : [leaf] "{eax}" (leaf),
    );

    return CPUID{
        .eax = eax,
        .ebx = ebx,
        .edx = edx,
        .ecx = ecx,
    };
}

//const PAT = struct {
//value: u64,
//uncacheable: ?Index,
//write_combining: ?Index,
//write_through: ?Index,
//write_back: ?Index,

//const Index = u3;
//const EncodingInt = u3;
//const Encoding = enum(EncodingInt) {
//UC = 0,
//WC = 1,
//WT = 4,
//WP = 5,
//WB = 6,
//UC_ = 7,
//};

//const msr = MSR(0x277);

//fn init() PAT {
//const id = cpuid(0x00000001);
//kernel.assert(@truncate(u1, id.edx >> 16) == 1, @src());
//const value = msr.read();

//return PAT{
//.value = value,
//.uncacheable = find_index(value, Encoding.UC),
//.write_combining = find_index(value, Encoding.WC),
//.write_through = find_index(value, Encoding.WT),
//.write_back = find_index(value, Encoding.WB),
//};
//}

//inline fn find_index(pat: u64, comptime encoding: Encoding) ?Index {
//if (@truncate(EncodingInt, pat >> (@as(u6, 0) * 8)) == @enumToInt(encoding)) return 0;
//if (@truncate(EncodingInt, pat >> (@as(u6, 1) * 8)) == @enumToInt(encoding)) return 1;
//if (@truncate(EncodingInt, pat >> (@as(u6, 2) * 8)) == @enumToInt(encoding)) return 2;
//if (@truncate(EncodingInt, pat >> (@as(u6, 3) * 8)) == @enumToInt(encoding)) return 3;
//if (@truncate(EncodingInt, pat >> (@as(u6, 4) * 8)) == @enumToInt(encoding)) return 4;
//if (@truncate(EncodingInt, pat >> (@as(u6, 5) * 8)) == @enumToInt(encoding)) return 5;
//if (@truncate(EncodingInt, pat >> (@as(u6, 6) * 8)) == @enumToInt(encoding)) return 6;
//if (@truncate(EncodingInt, pat >> (@as(u6, 7) * 8)) == @enumToInt(encoding)) return 7;

//return null;
//}
//};
