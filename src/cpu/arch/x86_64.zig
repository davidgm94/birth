const lib = @import("lib");
const Allocator = lib.Allocator;
const assert = lib.assert;
const ELF = lib.ELF(64);
const log = lib.log;
const Spinlock = lib.Spinlock;
const bootloader = @import("bootloader");
const privileged = @import("privileged");
const panic = cpu.panic;
const PageAllocator = cpu.PageAllocator;
const x86_64 = privileged.arch.x86_64;
const APIC = x86_64.APIC;
const paging = x86_64.paging;
const TSS = x86_64.TSS;
const cr0 = x86_64.registers.cr0;
const cr3 = x86_64.registers.cr3;
const cr4 = x86_64.registers.cr4;
const IA32_APIC_BASE = x86_64.registers.IA32_APIC_BASE;
const IA32_EFER = x86_64.registers.IA32_EFER;
const IA32_FSTAR = x86_64.registers.IA32_FSTAR;
const IA32_FMASK = x86_64.registers.IA32_FMASK;
const IA32_LSTAR = x86_64.registers.IA32_LSTAR;
const IA32_STAR = x86_64.registers.IA32_STAR;
const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const VirtualAddress = privileged.VirtualAddress;
const VirtualMemoryRegion = privileged.VirtualMemoryRegion;

const cpu = @import("cpu");
const Heap = cpu.Heap;
const VirtualAddressSpace = cpu.VirtualAddressSpace;

const rise = @import("rise");

pub const kpti = true;
pub const pcid = false;
pub const smap = false;
pub const invariant_tsc = false;

const user_scheduler_virtual_address = VirtualAddress.new(0x1_000_000);

pub const writer = privileged.E9Writer{ .context = {} };
var writer_lock: Spinlock = .released;

const capability_address_space_size = 1 * lib.gb;
const capability_address_space_start = capability_address_space_stack_top - capability_address_space_size;
const capability_address_space_stack_top = 0xffff_ffff_8000_0000;
const capability_address_space_stack_size = privileged.default_stack_size;
const capability_address_space_stack_address = capability_address_space_stack_top - capability_address_space_stack_size;

const local_timer_vector = 0xef;
const pcid_bit = 11;
const pcid_mask = 1 << pcid_bit;
const cr3_user_page_table_mask = 1 << @bitOffsetOf(cr3, "address");
const cr3_user_page_table_and_pcid_mask = cr3_user_page_table_mask | pcid_mask;

const init_address_space_limit = 128 * lib.mb;
const init_pdpt_size = paging.pdptEntries(init_address_space_limit);
const init_pdt_size = paging.pdtEntries(init_address_space_limit);
const init_pt_size = paging.ptEntries(init_address_space_limit);

pub const Registers = extern struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    syscall_number_or_error_code: u64,
    rip: u64,
    cs: u64,
    rflags: lib.arch.x86_64.registers.RFLAGS,
    rsp: u64,
    ss: u64,
};

const interrupt_handlers = [256]*const fn () callconv(.Naked) noreturn{
    InterruptHandler(@enumToInt(Interrupt.DE), false),
    InterruptHandler(@enumToInt(Interrupt.DB), false),
    InterruptHandler(@enumToInt(Interrupt.NMI), false),
    InterruptHandler(@enumToInt(Interrupt.BP), false),
    InterruptHandler(@enumToInt(Interrupt.OF), false),
    InterruptHandler(@enumToInt(Interrupt.BR), false),
    InterruptHandler(@enumToInt(Interrupt.UD), false),
    InterruptHandler(@enumToInt(Interrupt.NM), false),
    InterruptHandler(@enumToInt(Interrupt.DF), true),
    InterruptHandler(@enumToInt(Interrupt.CSO), false),
    InterruptHandler(@enumToInt(Interrupt.TS), true),
    InterruptHandler(@enumToInt(Interrupt.NP), true),
    InterruptHandler(@enumToInt(Interrupt.SS), true),
    InterruptHandler(@enumToInt(Interrupt.GP), true),
    InterruptHandler(@enumToInt(Interrupt.PF), true),
    InterruptHandler(0x0f, false),
    InterruptHandler(@enumToInt(Interrupt.MF), false),
    InterruptHandler(@enumToInt(Interrupt.AC), true),
    InterruptHandler(@enumToInt(Interrupt.MC), false),
    InterruptHandler(@enumToInt(Interrupt.XM), false),
    InterruptHandler(@enumToInt(Interrupt.VE), false),
    InterruptHandler(@enumToInt(Interrupt.CP), true),
    InterruptHandler(0x16, false),
    InterruptHandler(0x17, false),
    InterruptHandler(0x18, false),
    InterruptHandler(0x19, false),
    InterruptHandler(0x1a, false),
    InterruptHandler(0x1b, false),
    InterruptHandler(0x1c, false),
    InterruptHandler(0x1d, false),
    InterruptHandler(0x1e, false),
    InterruptHandler(0x1f, false),
    InterruptHandler(0x20, false),
    InterruptHandler(0x21, false),
    InterruptHandler(0x22, false),
    InterruptHandler(0x23, false),
    InterruptHandler(0x24, false),
    InterruptHandler(0x25, false),
    InterruptHandler(0x26, false),
    InterruptHandler(0x27, false),
    InterruptHandler(0x28, false),
    InterruptHandler(0x29, false),
    InterruptHandler(0x2a, false),
    InterruptHandler(0x2b, false),
    InterruptHandler(0x2c, false),
    InterruptHandler(0x2d, false),
    InterruptHandler(0x2e, false),
    InterruptHandler(0x2f, false),
    InterruptHandler(0x30, false),
    InterruptHandler(0x31, false),
    InterruptHandler(0x32, false),
    InterruptHandler(0x33, false),
    InterruptHandler(0x34, false),
    InterruptHandler(0x35, false),
    InterruptHandler(0x36, false),
    InterruptHandler(0x37, false),
    InterruptHandler(0x38, false),
    InterruptHandler(0x39, false),
    InterruptHandler(0x3a, false),
    InterruptHandler(0x3b, false),
    InterruptHandler(0x3c, false),
    InterruptHandler(0x3d, false),
    InterruptHandler(0x3e, false),
    InterruptHandler(0x3f, false),
    InterruptHandler(0x40, false),
    InterruptHandler(0x41, false),
    InterruptHandler(0x42, false),
    InterruptHandler(0x43, false),
    InterruptHandler(0x44, false),
    InterruptHandler(0x45, false),
    InterruptHandler(0x46, false),
    InterruptHandler(0x47, false),
    InterruptHandler(0x48, false),
    InterruptHandler(0x49, false),
    InterruptHandler(0x4a, false),
    InterruptHandler(0x4b, false),
    InterruptHandler(0x4c, false),
    InterruptHandler(0x4d, false),
    InterruptHandler(0x4e, false),
    InterruptHandler(0x4f, false),
    InterruptHandler(0x50, false),
    InterruptHandler(0x51, false),
    InterruptHandler(0x52, false),
    InterruptHandler(0x53, false),
    InterruptHandler(0x54, false),
    InterruptHandler(0x55, false),
    InterruptHandler(0x56, false),
    InterruptHandler(0x57, false),
    InterruptHandler(0x58, false),
    InterruptHandler(0x59, false),
    InterruptHandler(0x5a, false),
    InterruptHandler(0x5b, false),
    InterruptHandler(0x5c, false),
    InterruptHandler(0x5d, false),
    InterruptHandler(0x5e, false),
    InterruptHandler(0x5f, false),
    InterruptHandler(0x60, false),
    InterruptHandler(0x61, false),
    InterruptHandler(0x62, false),
    InterruptHandler(0x63, false),
    InterruptHandler(0x64, false),
    InterruptHandler(0x65, false),
    InterruptHandler(0x66, false),
    InterruptHandler(0x67, false),
    InterruptHandler(0x68, false),
    InterruptHandler(0x69, false),
    InterruptHandler(0x6a, false),
    InterruptHandler(0x6b, false),
    InterruptHandler(0x6c, false),
    InterruptHandler(0x6d, false),
    InterruptHandler(0x6e, false),
    InterruptHandler(0x6f, false),
    InterruptHandler(0x70, false),
    InterruptHandler(0x71, false),
    InterruptHandler(0x72, false),
    InterruptHandler(0x73, false),
    InterruptHandler(0x74, false),
    InterruptHandler(0x75, false),
    InterruptHandler(0x76, false),
    InterruptHandler(0x77, false),
    InterruptHandler(0x78, false),
    InterruptHandler(0x79, false),
    InterruptHandler(0x7a, false),
    InterruptHandler(0x7b, false),
    InterruptHandler(0x7c, false),
    InterruptHandler(0x7d, false),
    InterruptHandler(0x7e, false),
    InterruptHandler(0x7f, false),
    InterruptHandler(0x80, false),
    InterruptHandler(0x81, false),
    InterruptHandler(0x82, false),
    InterruptHandler(0x83, false),
    InterruptHandler(0x84, false),
    InterruptHandler(0x85, false),
    InterruptHandler(0x86, false),
    InterruptHandler(0x87, false),
    InterruptHandler(0x88, false),
    InterruptHandler(0x89, false),
    InterruptHandler(0x8a, false),
    InterruptHandler(0x8b, false),
    InterruptHandler(0x8c, false),
    InterruptHandler(0x8d, false),
    InterruptHandler(0x8e, false),
    InterruptHandler(0x8f, false),
    InterruptHandler(0x90, false),
    InterruptHandler(0x91, false),
    InterruptHandler(0x92, false),
    InterruptHandler(0x93, false),
    InterruptHandler(0x94, false),
    InterruptHandler(0x95, false),
    InterruptHandler(0x96, false),
    InterruptHandler(0x97, false),
    InterruptHandler(0x98, false),
    InterruptHandler(0x99, false),
    InterruptHandler(0x9a, false),
    InterruptHandler(0x9b, false),
    InterruptHandler(0x9c, false),
    InterruptHandler(0x9d, false),
    InterruptHandler(0x9e, false),
    InterruptHandler(0x9f, false),
    InterruptHandler(0xa0, false),
    InterruptHandler(0xa1, false),
    InterruptHandler(0xa2, false),
    InterruptHandler(0xa3, false),
    InterruptHandler(0xa4, false),
    InterruptHandler(0xa5, false),
    InterruptHandler(0xa6, false),
    InterruptHandler(0xa7, false),
    InterruptHandler(0xa8, false),
    InterruptHandler(0xa9, false),
    InterruptHandler(0xaa, false),
    InterruptHandler(0xab, false),
    InterruptHandler(0xac, false),
    InterruptHandler(0xad, false),
    InterruptHandler(0xae, false),
    InterruptHandler(0xaf, false),
    InterruptHandler(0xb0, false),
    InterruptHandler(0xb1, false),
    InterruptHandler(0xb2, false),
    InterruptHandler(0xb3, false),
    InterruptHandler(0xb4, false),
    InterruptHandler(0xb5, false),
    InterruptHandler(0xb6, false),
    InterruptHandler(0xb7, false),
    InterruptHandler(0xb8, false),
    InterruptHandler(0xb9, false),
    InterruptHandler(0xba, false),
    InterruptHandler(0xbb, false),
    InterruptHandler(0xbc, false),
    InterruptHandler(0xbd, false),
    InterruptHandler(0xbe, false),
    InterruptHandler(0xbf, false),
    InterruptHandler(0xc0, false),
    InterruptHandler(0xc1, false),
    InterruptHandler(0xc2, false),
    InterruptHandler(0xc3, false),
    InterruptHandler(0xc4, false),
    InterruptHandler(0xc5, false),
    InterruptHandler(0xc6, false),
    InterruptHandler(0xc7, false),
    InterruptHandler(0xc8, false),
    InterruptHandler(0xc9, false),
    InterruptHandler(0xca, false),
    InterruptHandler(0xcb, false),
    InterruptHandler(0xcc, false),
    InterruptHandler(0xcd, false),
    InterruptHandler(0xce, false),
    InterruptHandler(0xcf, false),
    InterruptHandler(0xd0, false),
    InterruptHandler(0xd1, false),
    InterruptHandler(0xd2, false),
    InterruptHandler(0xd3, false),
    InterruptHandler(0xd4, false),
    InterruptHandler(0xd5, false),
    InterruptHandler(0xd6, false),
    InterruptHandler(0xd7, false),
    InterruptHandler(0xd8, false),
    InterruptHandler(0xd9, false),
    InterruptHandler(0xda, false),
    InterruptHandler(0xdb, false),
    InterruptHandler(0xdc, false),
    InterruptHandler(0xdd, false),
    InterruptHandler(0xde, false),
    InterruptHandler(0xdf, false),
    InterruptHandler(0xe0, false),
    InterruptHandler(0xe1, false),
    InterruptHandler(0xe2, false),
    InterruptHandler(0xe3, false),
    InterruptHandler(0xe4, false),
    InterruptHandler(0xe5, false),
    InterruptHandler(0xe6, false),
    InterruptHandler(0xe7, false),
    InterruptHandler(0xe8, false),
    InterruptHandler(0xe9, false),
    InterruptHandler(0xea, false),
    InterruptHandler(0xeb, false),
    InterruptHandler(0xec, false),
    InterruptHandler(0xed, false),
    InterruptHandler(0xee, false),
    InterruptHandler(0xef, false),
    InterruptHandler(0xf0, false),
    InterruptHandler(0xf1, false),
    InterruptHandler(0xf2, false),
    InterruptHandler(0xf3, false),
    InterruptHandler(0xf4, false),
    InterruptHandler(0xf5, false),
    InterruptHandler(0xf6, false),
    InterruptHandler(0xf7, false),
    InterruptHandler(0xf8, false),
    InterruptHandler(0xf9, false),
    InterruptHandler(0xfa, false),
    InterruptHandler(0xfb, false),
    InterruptHandler(0xfc, false),
    InterruptHandler(0xfd, false),
    InterruptHandler(0xfe, false),
    InterruptHandler(0xff, false),
};

const interrupt_kind: u32 = 0;
const dispatch_count = IDT.entry_count;

const code_64 = @offsetOf(GDT, "code_64");
const data_64 = @offsetOf(GDT, "data_64");
const user_code_64 = @offsetOf(GDT, "user_code_64");
const user_data_64 = @offsetOf(GDT, "user_data_64");
const tss_selector = @offsetOf(GDT, "tss_descriptor");
const user_code_selector = user_code_64 | user_dpl;
const user_data_selector = user_data_64 | user_dpl;

comptime {
    assert(rise.arch.user_code_selector == user_code_selector);
    assert(rise.arch.user_data_selector == user_data_selector);
}

const user_dpl = 3;

export var interrupt_stack: [0x1000]u8 align(lib.arch.stack_alignment) = undefined;
export var gdt = GDT{};
export var tss = TSS{};
export var idt = IDT{};
export var user_stack: u64 = 0;
export var ticks_per_ms: privileged.arch.x86_64.TicksPerMS = undefined;

pub const GDT = extern struct {
    null: Entry = GDT.Entry.null_entry, // 0x00
    code_16: Entry = GDT.Entry.code_16, // 0x08
    data_16: Entry = GDT.Entry.data_16, // 0x10
    code_32: Entry = GDT.Entry.code_32, // 0x18
    data_32: Entry = GDT.Entry.data_32, // 0x20
    code_64: Entry = GDT.Entry.code_64, // 0x28
    data_64: Entry = GDT.Entry.data_64, // 0x30
    user_data_64: Entry = GDT.Entry.user_data_64, // 0x38
    user_code_64: Entry = GDT.Entry.user_code_64, // 0x40
    tss_descriptor: TSS.Descriptor = undefined, // 0x48

    const Entry = x86_64.GDT.Entry;

    const Descriptor = x86_64.GDT.Descriptor;

    comptime {
        const entry_count = 9;
        const target_size = entry_count * @sizeOf(Entry) + @sizeOf(TSS.Descriptor);

        assert(@sizeOf(GDT) == target_size);
        assert(@offsetOf(GDT, "code_64") == 0x28);
        assert(@offsetOf(GDT, "data_64") == 0x30);
        assert(@offsetOf(GDT, "user_data_64") == 0x38);
        assert(@offsetOf(GDT, "user_code_64") == 0x40);
        assert(@offsetOf(GDT, "tss_descriptor") == entry_count * @sizeOf(Entry));
    }

    pub fn getDescriptor(global_descriptor_table: *const GDT) GDT.Descriptor {
        return .{
            .limit = @sizeOf(GDT) - 1,
            .address = @ptrToInt(global_descriptor_table),
        };
    }
};

const Interrupt = enum(u5) {
    DE = 0x00,
    DB = 0x01,
    NMI = 0x02,
    BP = 0x03,
    OF = 0x04,
    BR = 0x05,
    UD = 0x06,
    NM = 0x07,
    DF = 0x08,
    CSO = 0x09, // Not used anymore
    TS = 0x0A,
    NP = 0x0B,
    SS = 0x0C,
    GP = 0x0D,
    PF = 0x0E,
    MF = 0x10,
    AC = 0x11,
    MC = 0x12,
    XM = 0x13,
    VE = 0x14,
    CP = 0x15,
    _,
};

pub const root_page_table_entry = PageTableEntry.pml4;

pub const PageTableEntry = enum(u3) {
    pml5,
    pml4,
    pdp,
    pd,
    pt,
};

pub fn entryPoint() callconv(.Naked) noreturn {
    asm volatile (
        \\lea stack(%rip), %rsp
        \\add %[stack_len], %rsp
        \\pushq $0
        \\mov %rsp, %rbp
        \\jmp main
        \\cli
        \\hlt
        :
        : [stack_len] "i" (cpu.stack.len),
        : "rsp", "rbp"
    );

    unreachable;
}

const InitializationError = error{
    feature_requested_and_not_available,
    no_files,
    cpu_file_not_found,
    init_file_not_found,
};

pub export fn main(bootloader_information: *bootloader.Information) callconv(.C) noreturn {
    log.info("Initializing...\n\n\t[BUILD MODE] {s}\n\t[BOOTLOADER] {s}\n\t[BOOT PROTOCOL] {s}\n", .{ @tagName(lib.build_mode), @tagName(bootloader_information.bootloader), @tagName(bootloader_information.protocol) });
    archInitialize(bootloader_information) catch |err| {
        cpu.panicWithStackTrace(@errorReturnTrace(), "Failed to initialize CPU: {}", .{err});
    };
}

fn archInitialize(bootloader_information: *bootloader.Information) !noreturn {
    bootloader_information.draw_context.clearScreen(0xffff7f50);
    // Do an integrity check so that the bootloader information is in perfect state and there is no weird memory behavior.
    // This is mainly due to the transition from a 32-bit bootloader to a 64-bit CPU driver in the x86-64 architecture.
    try bootloader_information.checkIntegrity();
    // Informing the bootloader information struct that we have reached the CPU driver and any bootloader
    // functionality is not available anymore
    bootloader_information.stage = .cpu;
    // Check that the bootloader has loaded some files as the CPU driver needs them to go forward
    if (bootloader_information.getSlice(.files).len == 0) return InitializationError.no_files;

    const cpuid = lib.arch.x86_64.cpuid;
    if (pcid) {
        if (cpuid(1).ecx & (1 << 17) == 0) return InitializationError.feature_requested_and_not_available;
    }

    if (invariant_tsc) {
        if (cpuid(0x80000007).edx & (1 << 8) == 0) return InitializationError.feature_requested_and_not_available;
    }

    // Initialize GDT
    const gdt_descriptor = GDT.Descriptor{
        .limit = @sizeOf(GDT) - 1,
        .address = @ptrToInt(&gdt),
    };

    asm volatile (
        \\lgdt %[gdt]
        \\mov %[ds], %rax
        \\movq %rax, %ds
        \\movq %rax, %es
        \\movq %rax, %fs
        \\movq %rax, %gs
        \\movq %rax, %ss
        \\pushq %[cs]
        \\lea 1f(%rip), %rax
        \\pushq %rax
        \\lretq
        \\1:
        :
        : [gdt] "*p" (&gdt_descriptor),
          [ds] "i" (data_64),
          [cs] "i" (code_64),
        : "memory"
    );

    const tss_address = @ptrToInt(&tss);
    gdt.tss_descriptor = .{
        .limit_low = @truncate(u16, @sizeOf(TSS)),
        .base_low = @truncate(u16, tss_address),
        .base_mid_low = @truncate(u8, tss_address >> 16),
        .access = .{
            .type = .tss_available,
            .dpl = 0,
            .present = true,
        },
        .attributes = .{
            .limit = @truncate(u4, @sizeOf(TSS) >> 16),
            .available_for_system_software = false,
            .granularity = false,
        },
        .base_mid_high = @truncate(u8, tss_address >> 24),
        .base_high = @truncate(u32, tss_address >> 32),
    };

    tss.rsp[0] = @ptrToInt(&interrupt_stack) + interrupt_stack.len;
    asm volatile (
        \\ltr %[tss_selector]
        :
        : [tss_selector] "r" (@as(u16, tss_selector)),
        : "memory"
    );

    // Initialize IDT

    for (&idt.descriptors, interrupt_handlers, 0..) |*descriptor, interrupt_handler, i| {
        const interrupt_address = @ptrToInt(interrupt_handler);
        descriptor.* = .{
            .offset_low = @truncate(u16, interrupt_address),
            .segment_selector = code_64,
            .flags = .{
                .ist = 0,
                .type = if (i < 32) .trap_gate else .interrupt_gate,
                .dpl = 0,
                .present = true,
            },
            .offset_mid = @truncate(u16, interrupt_address >> 16),
            .offset_high = @truncate(u32, interrupt_address >> 32),
        };
    }

    const idt_descriptor = IDT.Descriptor{
        .limit = @sizeOf(IDT) - 1,
        .address = @ptrToInt(&idt),
    };

    asm volatile (
        \\lidt %[idt_descriptor]
        :
        : [idt_descriptor] "*p" (&idt_descriptor),
        : "memory"
    );

    // Mask PIC
    privileged.arch.io.write(u8, 0xa1, 0xff);
    privileged.arch.io.write(u8, 0x21, 0xff);

    asm volatile ("sti" ::: "memory");

    cpu.bsp = IA32_APIC_BASE.read().bsp;

    const star = IA32_STAR{
        .kernel_cs = code_64,
        .user_cs_anchor = data_64,
    };

    comptime {
        assert(data_64 == star.kernel_cs + 8);
        assert(star.user_cs_anchor == user_data_64 - 8);
        assert(star.user_cs_anchor == user_code_64 - 16);
    }

    star.write();

    IA32_LSTAR.write(@ptrToInt(&syscallEntryPoint));
    const syscall_mask = privileged.arch.x86_64.registers.syscall_mask;
    IA32_FMASK.write(syscall_mask);

    // Enable syscall extensions
    var efer = IA32_EFER.read();
    efer.SCE = true;
    efer.write();

    var my_cr4 = cr4.read();
    my_cr4.operating_system_support_for_fx_save_restore = true;
    my_cr4.operating_system_support_for_unmasked_simd_fp_exceptions = true;
    my_cr4.page_global_enable = true;
    my_cr4.performance_monitoring_counter_enable = true;
    my_cr4.write();

    var my_cr0 = cr0.read();
    my_cr0.monitor_coprocessor = true;
    my_cr0.emulation = false;
    my_cr0.numeric_error = true;
    my_cr0.task_switched = false;
    my_cr0.write();

    var ia32_apic_base = IA32_APIC_BASE.read();
    comptime {
        assert(lib.arch.valid_page_sizes[0] == 0x1000);
    }

    // The bootloader already mapped APIC

    // const apic_base_physical_address = ia32_apic_base.getAddress();
    // const minimal_paging = paging.Specific{
    //     .cr3 = cr3.read(),
    // };

    // try minimal_paging.map(apic_base_physical_address, apic_base_physical_address.toHigherHalfVirtualAddress(), lib.arch.valid_page_sizes[0], .{
    //     .write = true,
    //     .cache_disable = true,
    //     .global = true,
    // }, apic_page_allocator_interface);

    const spurious_vector: u8 = 0xFF;
    APIC.write(.spurious, @as(u32, 0x100) | spurious_vector);

    const tpr = APIC.TaskPriorityRegister{};
    tpr.write();

    const lvt_timer = APIC.LVTTimer{};
    lvt_timer.write();

    ia32_apic_base.global_enable = true;
    ia32_apic_base.write();

    ticks_per_ms = APIC.calibrateTimer();

    cpu.core_id = APIC.read(.id);

    asm volatile (
        \\fninit
        // TODO: figure out why this crashes with KVM
        //\\ldmxcsr %[mxcsr]
        :: //[mxcsr] "m" (@as(u32, 0x1f80)),
        : "memory");

    x86_64.registers.IA32_FS_BASE.write(user_scheduler_virtual_address.value());

    // TODO: configure PAT

    try initialize(bootloader_information);
}

const BSPEarlyAllocator = extern struct {
    base: PhysicalAddress,
    size: usize,
    offset: usize,
    allocator: Allocator = .{
        .callbacks = .{
            .allocate = callbackAllocate,
        },
    },
    heap_first: ?*BSPHeapEntry = null,

    const BSPHeapEntry = extern struct {
        virtual_memory_region: VirtualMemoryRegion,
        offset: usize = 0,
        next: ?*BSPHeapEntry = null,

        // pub fn create(heap: *BSPHeapEntry, comptime T: type) !*T {
        //     _ = heap;
        //     @panic("TODO: create");
        // }

        pub fn allocateBytes(heap: *BSPHeapEntry, size: u64, alignment: u64) ![]u8 {
            assert(alignment < lib.arch.valid_page_sizes[0]);
            assert(heap.virtual_memory_region.size > size);
            if (!lib.isAligned(heap.virtual_memory_region.address.value(), alignment)) {
                const misalignment = lib.alignForward(heap.virtual_memory_region.address.value(), alignment) - heap.virtual_memory_region.address.value();
                _ = heap.virtual_memory_region.takeSlice(misalignment);
            }

            return heap.virtual_memory_region.takeByteSlice(size);
        }
    };

    pub fn createPageAligned(allocator: *BSPEarlyAllocator, comptime T: type) AllocatorError!*align(lib.arch.valid_page_sizes[0]) T {
        return @ptrCast(*align(lib.arch.valid_page_sizes[0]) T, try allocator.allocateBytes(@sizeOf(T)));
    }

    pub fn allocateBytes(allocator: *BSPEarlyAllocator, size: u64) AllocatorError![]align(lib.arch.valid_page_sizes[0]) u8 {
        if (!lib.isAligned(size, lib.arch.valid_page_sizes[0])) return AllocatorError.bad_alignment;
        if (allocator.offset + size > allocator.size) return AllocatorError.out_of_memory;

        const physical_address = allocator.base.offset(allocator.offset);
        allocator.offset += size;
        const slice = physical_address.toHigherHalfVirtualAddress().access([*]align(lib.arch.valid_page_sizes[0]) u8)[0..size];
        @memset(slice, 0);

        return slice;
    }

    pub fn callbackAllocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
        const early_allocator = @fieldParentPtr(BSPEarlyAllocator, "allocator", allocator);
        if (alignment == lib.arch.valid_page_sizes[0] or size % lib.arch.valid_page_sizes[0] == 0) {
            const result = early_allocator.allocateBytes(size) catch return Allocator.Allocate.Error.OutOfMemory;
            return .{
                .address = @ptrToInt(result.ptr),
                .size = result.len,
            };
        } else if (alignment > lib.arch.valid_page_sizes[0]) {
            @panic("WTF");
        } else {
            assert(size < lib.arch.valid_page_sizes[0]);
            const heap_entry_allocation = early_allocator.allocateBytes(lib.arch.valid_page_sizes[0]) catch return Allocator.Allocate.Error.OutOfMemory;
            const heap_entry_region = VirtualMemoryRegion.fromByteSlice(heap_entry_allocation);
            const heap_entry = try early_allocator.addHeapRegion(heap_entry_region);
            const result = try heap_entry.allocateBytes(size, alignment);
            return .{
                .address = @ptrToInt(result.ptr),
                .size = result.len,
            };
        }
    }

    inline fn addHeapRegion(early_allocator: *BSPEarlyAllocator, region: VirtualMemoryRegion) !*BSPHeapEntry {
        const heap_entry = region.address.access(*BSPHeapEntry);
        const offset = @sizeOf(BSPHeapEntry);
        heap_entry.* = .{
            .offset = offset,
            .virtual_memory_region = region.offset(offset),
            .next = early_allocator.heap_first,
        };

        early_allocator.heap_first = heap_entry;

        return heap_entry;
    }
    const AllocatorError = error{
        out_of_memory,
        bad_alignment,
    };
};

fn initialize(bootloader_information: *bootloader.Information) !noreturn {
    const memory_map_entries = bootloader_information.getMemoryMapEntries();
    const page_counters = bootloader_information.getPageCounters();

    var best: usize = 0;
    var best_free_size: usize = 0;
    for (memory_map_entries, page_counters, 0..) |memory_map_entry, page_counter, index| {
        if (memory_map_entry.type != .usable or !lib.isAligned(memory_map_entry.region.size, lib.arch.valid_page_sizes[0]) or memory_map_entry.region.address.value() < lib.mb) {
            continue;
        }

        const busy_page_count = page_counter;
        const busy_size = busy_page_count << comptime lib.arch.page_shifter(lib.arch.valid_page_sizes[0]);
        const free_size = memory_map_entry.region.size - busy_size;
        if (free_size > best_free_size) {
            best = index;
            best_free_size = free_size;
            log.debug("Busy size: 0x{x}", .{busy_size});
        }
    }

    log.debug("Best free size: 0x{x}. Index: {}", .{ best_free_size, best });
    switch (cpu.bsp) {
        true => {
            var early_allocator = BSPEarlyAllocator{
                .base = memory_map_entries[best].region.address.offset(memory_map_entries[best].region.size - best_free_size),
                .size = best_free_size,
                .offset = 0,
            };
            cpu.driver = try early_allocator.createPageAligned(cpu.Driver);
            const init_module = bootloader_information.fetchFileByType(.init) orelse return InitializationError.init_file_not_found;
            try spawnInitBSP(init_module, &early_allocator.allocator);
        },
        false => @panic("Implement APP"),
    }

    // assert(cpu.bsp);
    // // As the bootloader information allocators are not now available, a page allocator pinned to the BSP core is set up here.
    // cpu.page_tables = bootloader_information.cpu_page_tables;
    // cpu.page_allocator = try PageAllocator.fromBSP(bootloader_information);
    // cpu.heap_allocator = try Heap.fromPageAllocator(&cpu.page_allocator);
    // cpu.file = for (bootloader_information.getFiles()) |file_descriptor| {
    //     if (file_descriptor.type == .cpu) break file_descriptor.getContent(bootloader_information);
    // } else return InitializationError.cpu_file_not_found;
    //
    // cpu.driver = try cpu.heap_allocator.create(cpu.Driver);
}

pub const IDT = extern struct {
    descriptors: [entry_count]GateDescriptor = undefined,
    pub const Descriptor = x86_64.SegmentDescriptor;
    pub const GateDescriptor = extern struct {
        offset_low: u16,
        segment_selector: u16,
        flags: packed struct(u16) {
            ist: u3,
            reserved: u5 = 0,
            type: x86_64.SystemSegmentDescriptor.Type,
            reserved1: u1 = 0,
            dpl: u2,
            present: bool,
        },
        offset_mid: u16,
        offset_high: u32,
        reserved: u32 = 0,

        comptime {
            assert(@sizeOf(@This()) == 0x10);
        }
    };
    pub const entry_count = 256;
};

export fn interruptHandler(regs: *const InterruptRegisters, interrupt_number: u8) void {
    switch (interrupt_number) {
        local_timer_vector => {
            APIC.write(.eoi, 0);
            nextTimer(10);
        },
        else => cpu.panicFromInstructionPointerAndFramePointer(regs.rip, regs.rbp, "Exception: 0x{x}", .{interrupt_number}),
    }
}

pub fn InterruptHandler(comptime interrupt_number: u64, comptime has_error_code: bool) fn () callconv(.Naked) noreturn {
    return struct {
        fn handler() callconv(.Naked) noreturn {
            asm volatile (
                \\endbr64
                ::: "memory");

            if (smap) {
                // TODO: Investigate why this is Exception #6
                asm volatile (
                    \\clac
                    ::: "memory");
            }

            asm volatile (
                \\cld
                ::: "memory");

            if (!has_error_code) {
                asm volatile ("pushq $0" ::: "memory");
            }

            asm volatile (
                \\push %rdi
                \\push %rsi
                \\push %rdx
                \\push %rcx
                \\push %rax
                \\push %r8
                \\push %r9
                \\push %r10
                \\push %r11
                \\pushq %rbx
                \\pushq %rbp
                \\push %r12
                \\push %r13
                \\push %r14
                \\push %r15
                \\mov %rsp, %rdi
                \\mov %[interrupt_number], %rsi
                \\call interruptHandler
                \\pop %r15
                \\pop %r14
                \\pop %r13
                \\pop %r12
                \\pop %rbp
                \\pop %rbx
                \\pop %r11
                \\pop %r10
                \\pop %r9
                \\pop %r8
                \\pop %rax
                \\pop %rcx
                \\pop %rdx
                \\pop %rsi
                \\pop %rdi
                :
                : [interrupt_number] "i" (interrupt_number),
                : "memory"
            );

            if (!has_error_code) {
                asm volatile (
                    \\add $0x8, %rsp
                    ::: "memory");
            }

            asm volatile (
                \\iretq
                \\int3
                ::: "memory");

            unreachable;
        }
    }.handler;
}

const InterruptRegisters = extern struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    error_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

/// SYSCALL documentation
/// ABI:
/// - RAX: System call number
/// - RCX: Return address
/// - R11: Saved rflags
/// - RDI: argument 0
/// - RSI: argument 1
/// - RDX: argument 2
/// - R10: argument 3
/// - R8:  argument 4
/// - R9:  argument 5
pub export fn syscallEntryPoint() callconv(.Naked) void {
    asm volatile (
        \\endbr64
        \\swapgs
        \\movq %rsp, user_stack(%rip)
    );

    if (kpti) {
        asm volatile (
            \\mov %cr3, %rsp
            ::: "memory");

        if (pcid) {
            @compileError("pcid support not yet implemented");
        }

        asm volatile (
            \\andq %[mask], %rsp
            \\mov %rsp, %cr3
            :
            : [mask] "i" (~@as(u64, cr3_user_page_table_and_pcid_mask)),
            : "memory"
        );
    }

    // Safe stack
    asm volatile ("movabsq %[capability_address_space_stack_top], %rsp"
        :
        : [capability_address_space_stack_top] "i" (capability_address_space_stack_top),
        : "memory", "rsp"
    );

    asm volatile (
        \\pushq %[user_ds]
        \\pushq (user_stack)
        \\pushq %r11
        \\pushq %[user_cs]
        \\pushq %rcx
        \\pushq %rax
        :
        : [user_ds] "i" (user_data_selector),
          [user_cs] "i" (user_code_selector),
        : "memory"
    );

    // Push and clear registers
    asm volatile (
    // Push
        \\pushq %rdi
        \\pushq %rsi
        \\pushq %rdx
        \\pushq %rcx
        \\pushq %rax
        \\pushq %r8
        \\pushq %r9
        \\pushq %r10
        \\pushq %r11
        \\pushq %rbx
        \\pushq %rbp
        \\pushq %r12
        \\pushq %r13
        \\pushq %r14
        \\pushq %r15
        // Clear
        \\xorl %esi, %esi
        \\xorl %edx, %edx
        \\xorl %ecx, %ecx
        \\xorl %r8d,  %r8d
        \\xorl %r9d,  %r9d
        \\xorl %r10d, %r10d
        \\xorl %r11d, %r11d
        \\xorl %ebx,  %ebx
        \\xorl %ebp,  %ebp
        \\xorl %r12d, %r12d
        \\xorl %r13d, %r13d
        \\xorl %r14d, %r14d
        \\xorl %r15d, %r15d
        ::: "memory");

    // Pass arguments
    asm volatile (
        \\mov %rsp, %rdi
        \\mov %rax, %rsi
        ::: "memory");

    // TODO: more security stuff
    asm volatile (
        \\call syscall
        ::: "memory");

    // TODO: more security stuff

    // Pop registers
    asm volatile (
        \\popq %r15
        \\popq %r14
        \\popq %r13
        \\popq %r12
        \\popq %rbp
        \\popq %rbx
        \\popq %r11
        \\popq %r10
        \\popq %r9
        \\popq %r8
        \\popq %rcx
        // RAX
        \\popq %rcx
        // RDX
        \\popq %rsi 
        \\popq %rsi
        \\popq %rdi
        ::: "memory");

    if (kpti) {
        // Restore CR3
        asm volatile (
            \\mov %cr3, %rsp
            ::: "memory");

        if (pcid) {
            @compileError("PCID not supported yet");
        }

        asm volatile (
            \\orq %[user_cr3_mask], %rsp
            \\mov %rsp, %cr3
            :
            : [user_cr3_mask] "i" (cr3_user_page_table_mask),
            : "memory"
        );
    }

    // Restore RSP
    asm volatile (
        \\mov user_stack(%rip), %rsp
        ::: "memory");

    asm volatile (
        \\swapgs
        \\sysretq
        ::: "memory");

    asm volatile (
        \\int3
        ::: "memory");

    unreachable;
}

const SyscallRegisters = extern struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    syscall_number: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

inline fn ok(result: struct {
    value: u64,
    another_value: u32 = 0,
    another_more_value: u8 = 0,
    flags: u7 = 0,
}) rise.syscall.Result {
    return .{
        .rise = .{
            .first = .{
                .padding1 = result.another_value,
                .@"error" = 0,
                .padding2 = result.another_more_value,
                .padding3 = result.flags,
                .convention = .rise,
            },
            .second = result.value,
        },
    };
}

/// SYSCALL documentation
/// ABI:
/// - RAX: System call options (number for Linux)
/// - RCX: Return address
/// - R11: Saved rflags
/// - RDI: argument 0
/// - RSI: argument 1
/// - RDX: argument 2
/// - R10: argument 3
/// - R8:  argument 4
/// - R9:  argument 5
export fn syscall(regs: *const SyscallRegisters) callconv(.C) rise.syscall.Result {
    const options = @bitCast(rise.syscall.Options, regs.syscall_number);
    const arguments = [_]u64{ regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9 };

    // TODO: check capability address
    switch (options.general.convention) {
        .rise => {
            if (cpu.user_scheduler.capability_root_node.hasPermissions(options.rise.type)) switch (options.rise.type) {
                .cpu => {
                    const command = @intToEnum(rise.capabilities.cpu, options.rise.command);
                    switch (command) {
                        .shutdown => privileged.exitFromQEMU(.success),
                        .get_core_id => return ok(.{
                            .value = cpu.core_id,
                        }),
                        // _ => @panic("Unknown cpu command"),
                    }
                },
                .io => {
                    const command = @intToEnum(rise.capabilities.io, options.rise.command);
                    switch (command) {
                        .stdout => {
                            const message_ptr = @intToPtr(?[*]const u8, arguments[0]) orelse @panic("message null");
                            const message_len = arguments[1];
                            const message = message_ptr[0..message_len];
                            writer.writeAll(message) catch unreachable;
                        },
                        _ => @panic("Unknown io command"),
                    }
                },
                else => @panic("TODO capabilities"),
                // _ => @panic("not implemented"),
            } else {
                return .{
                    .rise = .{
                        .first = .{
                            .@"error" = 1,
                        },
                        .second = 0,
                    },
                };
            }
        },
        .linux => @panic("linux syscall"),
    }

    return .{
        .rise = .{
            .first = .{},
            .second = 0,
        },
    };
}

fn spawnInitBSP(init_file: []const u8, allocator: *Allocator) !noreturn {
    const user_scheduler = try spawnInitCommon(allocator);
    _ = user_scheduler;
    const init_elf = try ELF.Parser.init(init_file);
    const entry_point = init_elf.getEntryPoint();
    const program_headers = init_elf.getProgramHeaders();

    const virtual_address_space = try VirtualAddressSpace.new();

    for (program_headers) |program_header| {
        if (program_header.type == .load) {
            const aligned_size = lib.alignForward(program_header.size_in_memory, lib.arch.valid_page_sizes[0]);
            const segment_virtual_address = VirtualAddress.new(program_header.virtual_address);
            const segment_flags = .{
                .execute = program_header.flags.executable,
                .write = program_header.flags.writable,
                .user = true,
            };

            const segment_physical_region = try virtual_address_space.allocateAndMapToAddress(segment_virtual_address, aligned_size, lib.arch.valid_page_sizes[0], segment_flags);

            const dst = segment_physical_region.toHigherHalfVirtualAddress().access(u8);
            const src = init_file[program_header.offset..][0..program_header.size_in_file];
            @memcpy(dst, src);
        }
    }
    _ = entry_point;
    //
    // const init_scheduler_allocation_size = 1 << 19;
    // const init_scheduler_common_physical_allocation = try virtual_address_space.allocateAndMapToAddress(user_scheduler_virtual_address, init_scheduler_allocation_size, lib.arch.valid_page_sizes[0], .{ .write = true, .user = true });
    // const init_scheduler_common_higher_half = init_scheduler_common_physical_allocation.address.toHigherHalfVirtualAddress().access(*rise.UserScheduler);
    // const init_scheduler_common_identity = user_scheduler_virtual_address.access(*rise.UserScheduler);
    // const init_scheduler_common_arch_higher_half = init_scheduler_common_higher_half.architectureSpecific();
    //
    // const init_scheduler = (try virtual_address_space.allocateAndMap(@sizeOf(cpu.UserScheduler), lib.arch.valid_page_sizes[0], .{ .write = true, .secret = true })).address.access(*cpu.UserScheduler);
    // init_scheduler.common = init_scheduler_common_identity;
    // init_scheduler.static_capability_bitmap.set(.cpu);
    // init_scheduler.static_capability_bitmap.set(.io);
    // cpu.user_scheduler = init_scheduler;
    //
    // const privileged_stack = try virtual_address_space.allocateAndMapToAddress(VirtualAddress.new(capability_address_space_stack_address), privileged.default_stack_size, lib.arch.valid_page_sizes[0], .{
    //     .write = true,
    //     .user = false,
    //     .secret = true,
    // });
    // _ = privileged_stack;
    //
    // const apic_base_physical_address = IA32_APIC_BASE.read().getAddress();
    // try virtual_address_space.map(apic_base_physical_address, apic_base_physical_address.toHigherHalfVirtualAddress(), lib.arch.valid_page_sizes[0], .{
    //     .global = false,
    //     .cache_disable = true,
    //     .write = true,
    // });
    //
    // init_scheduler_common_higher_half.self = init_scheduler_common_identity;
    // init_scheduler_common_higher_half.disabled = true;
    // // First argument
    // init_scheduler_common_arch_higher_half.disabled_save_area.registers.rdi = user_scheduler_virtual_address.value();
    // // Second argument
    // const is_init = true;
    // init_scheduler_common_arch_higher_half.disabled_save_area.registers.rsi = @boolToInt(is_init);
    // init_scheduler_common_arch_higher_half.disabled_save_area.registers.rip = entry_point;
    // init_scheduler_common_arch_higher_half.disabled_save_area.registers.rflags = .{ .IF = true };
    //
    // init_scheduler_common_arch_higher_half.disabled_save_area.fpu.fcw = 0x037f;
    // init_scheduler_common_arch_higher_half.disabled_save_area.fpu.mxcsr = 0x1f80;
    //
    // try virtual_address_space.mapPageTables();
    //
    // virtual_address_space.makeCurrent();
    //
    // init_scheduler_common_identity.architectureSpecific().disabled_save_area.contextSwitch();
    @panic("TODO: spawnInitBSP");
}

pub inline fn nextTimer(ms: u32) void {
    APIC.write(.lvt_timer, local_timer_vector | (1 << 17));
    APIC.write(.timer_initcnt, ticks_per_ms.lapic * ms);
}

const ApicPageAllocator = extern struct {
    pages: [4]PhysicalAddress = .{PhysicalAddress.invalid()} ** 4,

    const PageEntry = cpu.VirtualAddressSpace.PageEntry;

    fn allocate(context: ?*anyopaque, size: u64, alignment: u64, options: privileged.PageAllocator.AllocateOptions) Allocator.Allocate.Error!PhysicalMemoryRegion {
        const apic_allocator = @ptrCast(?*ApicPageAllocator, @alignCast(@alignOf(ApicPageAllocator), context)) orelse return Allocator.Allocate.Error.OutOfMemory;
        assert(size == lib.arch.valid_page_sizes[0]);
        assert(alignment == lib.arch.valid_page_sizes[0]);
        assert(options.count == 1);
        assert(options.level_valid);
        const physical_memory = try cpu.page_allocator.allocate(size, alignment);
        apic_allocator.pages[@enumToInt(options.level)] = physical_memory.address;
        return physical_memory;
    }
};

var apic_page_allocator = ApicPageAllocator{};
const apic_page_allocator_interface = privileged.PageAllocator{
    .allocate = ApicPageAllocator.allocate,
    .context = &apic_page_allocator,
    .context_type = .cpu,
};

pub inline fn writerStart() void {
    writer_lock.acquire();
}

pub inline fn writerEnd() void {
    writer_lock.release();
}

/// Architecture-specific implementation of mapping when you already can create user-space virtual address spaces
pub fn map(virtual_address_space: *VirtualAddressSpace, asked_physical_address: PhysicalAddress, asked_virtual_address: VirtualAddress, size: u64, general_flags: privileged.Mapping.Flags) !void {
    if (general_flags.user) {
        assert(!general_flags.secret);
    }

    try virtual_address_space.arch.map(asked_physical_address, asked_virtual_address, size, general_flags, virtual_address_space.getPageAllocatorInterface());
    if (!general_flags.secret) {
        const cpu_pml4 = try virtual_address_space.arch.getCpuPML4Table();
        const user_pml4 = try virtual_address_space.arch.getUserPML4Table();
        const first_indices = paging.computeIndices(asked_virtual_address.value());
        const last_indices = paging.computeIndices(asked_virtual_address.offset(size - lib.arch.valid_page_sizes[0]).value());
        const first_index = first_indices[@enumToInt(paging.Level.PML4)];
        const last_index = @intCast(u9, last_indices[@enumToInt(paging.Level.PML4)]) +| 1;

        for (cpu_pml4[first_index..last_index], user_pml4[first_index..last_index]) |cpu_pml4te, *user_pml4te| {
            user_pml4te.* = cpu_pml4te;
        }
    }
}

var once: bool = false;
fn spawnInitCommon(allocator: *Allocator) !*cpu.UserScheduler {
    assert(!once);
    once = true;

    // TODO: delete in the future
    assert(cpu.bsp);

    const root_capability_node = try spawnModule(allocator);
    const init_scheduler = root_capability_node.dynamic.scheduler.handle.?;
    try initPageTables(allocator, root_capability_node);

    if (true) privileged.exitFromQEMU(.success);

    return init_scheduler;
}

const page_table_entry_offset = @enumToInt(root_page_table_entry);
const page_table_entries = lib.enumValues(PageTableEntry)[page_table_entry_offset..];
const page_table_sizes = [lib.enumCount(PageTableEntry) - page_table_entry_offset]comptime_int{ paging.page_table_size, paging.page_table_size * init_pdpt_size, paging.page_table_size * init_pdpt_size * init_pdt_size, paging.page_table_size * init_pdpt_size * init_pdt_size * init_pt_size };
const page_table_total_size = blk: {
    var total: usize = 0;
    for (page_table_sizes) |size| {
        total += size;
    }

    break :blk total;
};

fn initPageTables(allocator: *Allocator, root: *cpu.capabilities.Root) !void {
    const page_table_allocation = try allocator.allocateBytes(page_table_total_size, lib.arch.valid_page_sizes[0]);
    var page_table_physical_region = PhysicalMemoryRegion.fromAllocation(page_table_allocation);

    assert(root.dynamic.page_tables.root.value() == 0);
    assert(root.dynamic.page_tables.first_block == null);
    assert(root.dynamic.page_tables.last_block == null);

    inline for (page_table_entries, page_table_sizes) |page_table_entry, level_size| {
        const iterations = comptime @divExact(level_size, paging.page_table_size);
        for (0..iterations) |_| {
            const page_table_physical_address = page_table_physical_region.takeSlice(paging.page_table_size).address;
            try root.addPageTable(allocator, page_table_physical_address, page_table_entry);
        }
    }
}

const scheduler_memory_size = 4 * lib.arch.valid_page_sizes[0];
fn spawnModule(allocator: *Allocator) !*cpu.capabilities.Root {
    cpu.driver.valid = true;
    const scheduler_memory = PhysicalMemoryRegion.fromAllocation(try allocator.allocateBytes(scheduler_memory_size, lib.arch.valid_page_sizes[0]));
    const scheduler = try allocator.create(cpu.UserScheduler);
    var root = cpu.capabilities.Root{
        .static = .{
            .cpu = true,
        },
        .dynamic = .{
            .scheduler = .{
                .handle = scheduler,
                .memory = scheduler_memory,
            },
            .page_tables = .{},
        },
    };
    const shared_scheduler_generic = scheduler_memory.address.toHigherHalfVirtualAddress().access(*rise.UserScheduler);
    shared_scheduler_generic.disabled = true;
    shared_scheduler_generic.core_id = cpu.core_id;
    root.dynamic.scheduler.handle.?.common = scheduler_memory.address.toIdentityMappedVirtualAddress().access(*rise.UserScheduler);
    root.dynamic.scheduler.handle.?.capability_root_node = root;
    return &root.dynamic.scheduler.handle.?.capability_root_node;
}
