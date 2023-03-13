const lib = @import("lib");
const Allocator = lib.Allocator;
const assert = lib.assert;
const log = lib.log;
const bootloader = @import("bootloader");
const privileged = @import("privileged");
const panic = privileged.panic;
const PageAllocator = privileged.PageAllocator;
const x86_64 = privileged.arch.x86_64;
const APIC = x86_64.APIC;
const paging = x86_64.paging;
const TSS = x86_64.TSS;
const registers = x86_64.registers;
const cr0 = registers.cr0;
const cr3 = registers.cr3;
const cr4 = registers.cr4;
const IA32_APIC_BASE = registers.IA32_APIC_BASE;
const IA32_EFER = registers.IA32_EFER;
const IA32_FSTAR = registers.IA32_FSTAR;
const IA32_FMASK = registers.IA32_FMASK;
const IA32_LSTAR = registers.IA32_LSTAR;
const IA32_STAR = registers.IA32_STAR;
const PhysicalAddress = privileged.PhysicalAddress;
const VirtualAddress = privileged.VirtualAddress;
const VirtualAddressSpace = privileged.VirtualAddressSpace;

const user_dpl = 3;

const code_64 = @offsetOf(GDT, "code_64");
const data_64 = @offsetOf(GDT, "data_64");
const user_code_64 = @offsetOf(GDT, "user_code_64");
const user_data_64 = @offsetOf(GDT, "user_data_64");
const tss_selector = @offsetOf(GDT, "tss_descriptor");
const user_code_selector = @offsetOf(GDT, "user_code_64") | user_dpl;
const user_data_selector = @offsetOf(GDT, "user_data_64") | user_dpl;

const cpu = @import("cpu");

pub const kpti = true;
pub const pcid = false;
pub const smap = false;

export var interrupt_stack: [0x1000]u8 align(0x10) linksection(".user_data") = undefined;
export var gdt linksection(".user_data") = GDT{};
export var tss linksection(".user_data") = TSS{};
export var idt linksection(".user_data") = IDT{};
export var user_stack: u64 linksection(".user_data") = 0;
export var syscall_stack: [0x1000]u8 align(0x1000) = undefined;

var bsp = false;

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

pub fn entryPoint() callconv(.Naked) noreturn {
    asm volatile (
        \\lea stack(%%rip), %%rsp
        \\add %[stack_len], %%rsp
        \\jmp *%[entry_point]
        \\cli
        \\hlt
        :
        : [entry_point] "r" (main),
          [stack_len] "i" (cpu.stack.len),
    );

    unreachable;
}

pub export fn main(bootloader_information: *bootloader.Information) callconv(.C) noreturn {
    log.debug("Hello! Bootloader information address: 0x{x}", .{@ptrToInt(bootloader_information)});

    if (pcid) {
        const cpuid = lib.arch.x86_64.cpuid(1);
        if (cpuid.ecx & (1 << 17) == 0) @panic("PCID not available");
    }

    // Do an integrity check so that the bootloader information is in perfect state and there is no weird memory behavior.
    // This is mainly due to the transition from a 32-bit bootloader to a 64-bit CPU driver in the x86-64 architecture.
    bootloader_information.checkIntegrity() catch |err| cpu.panic("Bootloader information size doesn't match: {}", .{err});
    // Check that the bootloader has loaded some files as the CPU driver needs them to go forward
    if (bootloader_information.getSlice(.files).len == 0) @panic("Files must be loaded by the bootloader");
    // Reset callbacks as there were 32-bit and calling them from here would be broken
    bootloader_information.page_allocator.callbacks.allocate = bootloader.Information.pageAllocate;
    bootloader_information.heap.allocator.callbacks.allocate = bootloader.Information.heapAllocate;
    // Informing the bootloader information struct that we have reached the CPU driver and any bootloader
    // functionality is not available anymore
    bootloader_information.stage = .cpu;

    cpu.mappings.text = bootloader_information.cpu_driver_mappings.text;
    cpu.mappings.rodata = bootloader_information.cpu_driver_mappings.rodata;
    cpu.mappings.data = bootloader_information.cpu_driver_mappings.data;

    // As the bootloader information allocators are not now available, a page allocator pinned to the BSP core is set up here.
    // TODO: figure out the best way to create page allocators for the APP cores
    log.debug("A", .{});
    cpu.page_allocator = PageAllocator.fromBSP(bootloader_information);
    log.debug("B", .{});

    cpu.virtual_address_space = .{
        .arch = bootloader_information.virtual_address_space.arch,
        .options = .{
            .user = false,
            .mapped_page_tables = true,
            .log_pages = false,
        },
        .backing_allocator = &cpu.page_allocator.allocator,
    };
    // Initialize GDT
    const gdt_descriptor = GDT.Descriptor{
        .limit = @sizeOf(GDT) - 1,
        .address = @ptrToInt(&gdt),
    };
    asm volatile (
        \\lgdt %[gdt]
        \\mov %[ds], %%rax
        \\movq %%rax, %%ds
        \\movq %%rax, %%es
        \\movq %%rax, %%fs
        \\movq %%rax, %%gs
        \\movq %%rax, %%ss
        \\pushq %[cs]
        \\lea 1f(%%rip), %%rax
        \\pushq %%rax
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

    const interrupt_address = @ptrToInt(&dummyInterruptHandler);
    log.debug("interrupt address: 0x{x}", .{interrupt_address});
    for (&idt.descriptors, 0..) |*descriptor, i| {
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

    log.debug("Loaded IDT", .{});

    // Mask PIC
    privileged.arch.io.write(u8, 0xa1, 0xff);
    privileged.arch.io.write(u8, 0x21, 0xff);

    log.debug("Masked PIC", .{});

    asm volatile ("sti" ::: "memory");
    log.debug("Enabled interrupts", .{});

    const ia32_apic_base = IA32_APIC_BASE.read();
    bsp = ia32_apic_base.bsp;

    initAPIC();

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
    // TODO: figure out what this does
    const syscall_mask = privileged.arch.x86_64.registers.syscall_mask;
    log.debug("Syscall mask: 0x{x}", .{syscall_mask});
    IA32_FMASK.write(syscall_mask);

    // Enable syscall extensions
    var efer = IA32_EFER.read();
    efer.SCE = true;
    efer.write();

    log.debug("Enabled syscalls", .{});

    var my_cr4 = cr4.read();
    my_cr4.operating_system_support_for_fx_save_restore = true;
    my_cr4.operating_system_support_for_unmasked_simd_fp_exceptions = true;
    my_cr4.page_global_enable = true;
    my_cr4.performance_monitoring_counter_enable = true;
    my_cr4.write();

    log.debug("Set up CR4", .{});

    var my_cr0 = cr0.read();
    my_cr0.monitor_coprocessor = true;
    my_cr0.emulation = false;
    my_cr0.numeric_error = true;
    my_cr0.task_switched = false;
    my_cr0.write();

    log.debug("Set up CR0", .{});

    asm volatile (
        \\fninit
        // TODO: figure out why this crashes with KVM
        //\\ldmxcsr %[mxcsr]
        :: //[mxcsr] "m" (@as(u32, 0x1f80)),
        : "memory");

    log.debug("Enabled FPU", .{});

    // TODO: configure PAT

    // TODO:
    kernelStartup(bootloader_information);
    log.debug("Is test: {}", .{lib.is_test});
    bootloader_information.draw_context.clearScreen(0xff005000);
    if (lib.is_test) {
        cpu.test_runner.runAllTests() catch @panic("Tests failed");
    }
    log.debug("Starting...", .{});

    todoEndEntryPoint();
}

fn todoEndEntryPoint() noreturn {
    @panic("end of entry point");
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

pub fn dummyInterruptHandler() linksection(".user_text") callconv(.Naked) noreturn {
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
        \\hlt
    );
    unreachable;
}

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
pub export fn syscallEntryPoint() linksection(".user_text") callconv(.Naked) void {
    asm volatile (
        \\endbr64
        \\swapgs
        \\movq %%rsp, user_stack(%%rip)
    );

    if (kpti) {
        asm volatile (
            \\mov %%cr3, %%rsp
            ::: "memory");

        if (pcid) {
            // TODO:
            @compileError("TODO: pcid");
        }

        asm volatile (
            \\andq %[mask], %rsp
            \\mov %rsp, %cr3
            :
            : [mask] "i" (~@as(u64, cr3_user_page_table_and_pcid_mask)),
            : "memory"
        );
    }

    asm volatile (
        \\lea syscall_stack(%%rip), %rsp
        \\add %[syscall_stack_size], %rsp
        :
        : [syscall_stack_size] "i" (syscall_stack.len),
        : "memory"
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
    // TODO: check if this works
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
        \\popq %r11
        \\popq %r10
        \\popq %r9
        \\popq %r8
        \\popq %rax
        \\popq %rcx
        \\popq %rdx
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
            : [user_cr3_mask] "i" (1 << @bitOffsetOf(cr3, "address")),
            : "memory"
        );
    }

    // Restore RSP
    asm volatile (
        \\mov user_stack(%%rip), %rsp
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
export fn syscall(regs: *const SyscallRegisters) callconv(.C) void {
    const syscall_arguments = lib.Syscall.Arguments{
        .number = @bitCast(lib.Syscall.Number, regs.syscall_number),
        .arguments = [_]u64{ regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9 },
    };

    switch (syscall_arguments.number.convention) {
        .rise => riseSyscall(@intToEnum(lib.Syscall.Rise, syscall_arguments.number.number), syscall_arguments.arguments),
        .linux => @panic("TODO: linux syscall"),
    }

    log.debug("Received syscall: {}", .{syscall_arguments});
}

inline fn riseSyscall(number: lib.Syscall.Rise, arguments: [6]u64) void {
    switch (number) {
        .qemu_exit => {
            privileged.exitFromQEMU(@intToEnum(lib.QEMU.ExitCode, arguments[0]));
        },
        //else => panic("Unknown syscall: {s}", .{@tagName(number)}),
    }

    @panic("Rise syscall");
}

const pcid_bit = 11;
const cr3_user_page_table_and_pcid_mask = (1 << @bitOffsetOf(cr3, "address")) | (1 << pcid_bit);

fn kernelStartup(bootloader_information: *bootloader.Information) noreturn {
    const init_director = switch (bsp) {
        true => dispatch(spawnBSPInit(bootloader_information.fetchFileByType(.init) orelse @panic("No init module found"))),
        false => @panic("APP"),
    };
    _ = init_director;

    @panic("TODO: kernel startup");
}

var current_director: ?*CoreDirectorData = null;

fn dispatch(director: *CoreDirectorData) noreturn {
    switch (director.disabled) {
        true => {
            // log.debug("FXRSTOR: 0x{x}", .{@ptrToInt(&director.shared.getDisabledSaveArea().fxsave_area)});
            resumeExecution(director.shared.getDisabledSaveArea());
        },
        false => {
            @panic("not disabled");
        },
    }
}

noinline fn resumeExecution(state: *align(16) Registers) linksection(".user_text") noreturn {
    const regs = state;
    asm volatile (
        \\pushq %[ss]
        \\pushq 7*8(%[registers])
        \\pushq %[rflags]
        \\pushq %[cs]
        \\pushq 16*8(%[registers])
        \\fxrstor %[fxsave_area]
        \\mov %[fs], %%fs
        \\mov %[gs], %%gs
        \\mov 17*8(%[registers]), %%rax
        \\mov %%rax, %%cr3
        \\mov 0*8(%[registers]), %%rax
        \\mov 2*8(%[registers]), %%rcx
        \\mov 3*8(%[registers]), %%rdx
        \\mov 4*8(%[registers]), %%rsi
        \\mov 5*8(%[registers]), %%rdi
        \\mov 6*8(%[registers]), %%rbp
        \\mov 8*8(%[registers]), %%r8
        \\mov 9*8(%[registers]), %%r9
        \\mov 10*8(%[registers]), %%r10
        \\mov 11*8(%[registers]), %%r11
        \\mov 12*8(%[registers]), %%r12
        \\mov 13*8(%[registers]), %%r13
        \\mov 14*8(%[registers]), %%r14
        \\mov 15*8(%[registers]), %%r15
        \\mov 1*8(%[registers]), %%rbx
        \\iretq
        :
        : [rsp] "{rsp}" (@ptrToInt(&interrupt_stack) + interrupt_stack.len),
          [registers] "{rbx}" (regs),
          [ss] "i" (user_data_selector),
          [cs] "i" (user_code_selector),
          [fs] "r" (regs.fs),
          [gs] "r" (regs.gs),
          [rflags] "r" (regs.rflags.user()),
          [fxsave_area] "*p" (&regs.fxsave_area),
    );

    while (true) {}
}

pub const CoreDirectorData = extern struct {
    shared: *CoreDirectorSharedGeneric,
    disabled: bool,
    //cspace: CTE,
    virtual_address_space: ?*VirtualAddressSpace,
    //dispatcher_cte: CTE,
    faults_taken: u32,
    is_vm_guest: bool,
    // TODO: guest desc
    domain_id: u64,
    // TODO: wakeup time
    wakeup_previous: ?*CoreDirectorData,
    wakeup_next: ?*CoreDirectorData,
    next: ?*CoreDirectorData,
    previous: ?*CoreDirectorData,

    pub fn contextSwitch(core_director_data: *CoreDirectorData) void {
        if (core_director_data.virtual_address_space) |virtual_address_space| {
            if (!virtual_address_space.options.mapped_page_tables) @panic("Page tables are not mapped before context switching");
            privileged.arch.paging.contextSwitch(virtual_address_space);
            context_switch_counter += 1;
        } else {
            @panic("VAS null");
        }
        // TODO: implement LDT
    }

    var context_switch_counter: usize = 0;
};

pub const CoreDirectorShared = extern struct {
    base: CoreDirectorSharedGeneric,
    crit_pc_low: VirtualAddress(.local),
    crit_pc_high: VirtualAddress(.local),
    ldt_base: VirtualAddress(.local),
    ldt_page_count: usize,

    enabled_save_area: Registers,
    disabled_save_area: Registers,
    trap_save_area: Registers,
};

pub const CoreDirectorSharedGeneric = extern struct {
    disabled: u32,
    haswork: u32,
    udisp: VirtualAddress(.local),
    lmp_delivered: u32,
    lmp_seen: u32,
    lmp_hint: VirtualAddress(.local),
    dispatcher_run: VirtualAddress(.local),
    dispatcher_lrpc: VirtualAddress(.local),
    dispatcher_page_fault: VirtualAddress(.local),
    dispatcher_page_fault_disabled: VirtualAddress(.local),
    dispatcher_trap: VirtualAddress(.local),
    // TODO: time
    systime_frequency: u64,
    core_id: u32,

    pub fn getDisabledSaveArea(core_director_shared_generic: *CoreDirectorSharedGeneric) *Registers {
        const core_director_shared_arch = @fieldParentPtr(CoreDirectorShared, "base", core_director_shared_generic);
        return &core_director_shared_arch.disabled_save_area;
    }
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
    cr3: u64,
    reserved: u64,
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
        assert(@sizeOf(Registers) == 688);
    }

    pub fn setParameter(regs: *Registers, param: u64) void {
        regs.rax = param;
    }
};

const ELF = lib.ELF(64);

// TODO: make this work with no KPTI
fn spawnBSPInit(init_file: []const u8) *CoreDirectorData {
    assert(bsp);

    const init_elf = ELF.Parser.init(init_file) catch @panic("can't parse elf");
    const entry_point = init_elf.getEntryPoint();
    log.debug("Entry point: 0x{x}", .{entry_point});
    const program_headers = init_elf.getProgramHeaders();

    const aligned_init_director_size = lib.alignForward(@sizeOf(CoreDirectorData), 0x1000);
    const aligned_init_director_shared_size = lib.alignForward(@sizeOf(CoreDirectorShared), 0x1000);
    const init_director_allocation = cpu.page_allocator.allocate(aligned_init_director_size, 0x1000) catch @panic("Core director allocation");
    const init_director_shared_allocation = cpu.page_allocator.allocate(aligned_init_director_shared_size, 0x1000) catch @panic("Core director shared allocation failed");

    log.debug("Init director allocation: 0x{x}. init_director_shared_allocation: 0x{x}", .{ init_director_allocation.address.value(), init_director_shared_allocation.address.value() });

    // TODO: don't waste this much space
    const virtual_address_space_allocation = cpu.page_allocator.allocator.allocateBytes(0x1000, 0x1000) catch @panic("virtual_address_space");
    const virtual_address_space_address = PhysicalAddress(.local).new(virtual_address_space_allocation.address);
    const virtual_address_space = virtual_address_space_address.toHigherHalfVirtualAddress().access(*VirtualAddressSpace);
    virtual_address_space.* = .{
        .arch = undefined,
        .options = .{
            .user = true,
            .mapped_page_tables = false,
            .log_pages = true,
        },
        .backing_allocator = &cpu.page_allocator.allocator,
    };

    // One for privileged mode, one for user
    const pml4_table_regions = virtual_address_space.allocatePageTables(@sizeOf(paging.PML4Table) * 2, 0x1000 * 2) catch @panic("pml4 regions");
    const cpu_side_pml4_physical_address = pml4_table_regions.address;
    const user_side_pml4_physical_address = pml4_table_regions.offset(0x1000).address;
    log.debug("CPU PML4: 0x{x}. User PML4: 0x{x}", .{ cpu_side_pml4_physical_address.value(), user_side_pml4_physical_address.value() });

    // Copy the higher half address mapping from cpu address space to user cpu-side address space
    log.debug("Higher half start", .{});
    paging.copyHigherHalf(cpu_side_pml4_physical_address);
    log.debug("Higher half end", .{});

    // First map vital parts for context switch
    virtual_address_space.arch = .{
        .cr3 = cr3.from_address(user_side_pml4_physical_address),
    };

    // Identity map dispatcher
    virtual_address_space.map(.local, init_director_allocation.address, init_director_allocation.address.toHigherHalfVirtualAddress(), aligned_init_director_size, .{ .write = true, .user = true }) catch @panic("user init director ");
    virtual_address_space.map(.local, init_director_shared_allocation.address, init_director_shared_allocation.address.toHigherHalfVirtualAddress(), aligned_init_director_shared_size, .{ .write = true, .user = true }) catch @panic("user init director shared");

    const init_director = init_director_allocation.address.toHigherHalfVirtualAddress().access(*CoreDirectorData);
    const init_director_shared = init_director_shared_allocation.address.toHigherHalfVirtualAddress().access(*CoreDirectorShared);
    init_director.shared = &init_director_shared.base;

    const text_start = @ptrToInt(&text_section_start);
    log.debug("Text start: 0x{x}", .{text_start});
    const data_start = @ptrToInt(&data_section_start);

    const user_text_offset = @ptrToInt(&user_text_start) - text_start;
    const user_data_offset = @ptrToInt(&user_data_start) - data_start;

    const user_text_size = @ptrToInt(&user_text_end) - @ptrToInt(&user_text_start);
    const user_data_size = @ptrToInt(&user_data_end) - @ptrToInt(&user_data_start);

    const user_text_physical_address = cpu.mappings.text.physical.offset(user_text_offset);
    log.debug("CPU mapping data: 0x{x}", .{cpu.mappings.data.physical.value()});
    const user_data_physical_address = cpu.mappings.data.physical.offset(user_data_offset);

    const user_text_virtual_address = VirtualAddress(.local).new(@ptrToInt(&user_text_start));
    const user_data_virtual_address = VirtualAddress(.local).new(@ptrToInt(&user_data_start));
    log.debug("Addresses: Text: 0x{x}. Data: 0x{x}", .{ user_text_virtual_address.value(), user_data_virtual_address.value() });
    log.debug("Size: Text: 0x{x}. Data: 0x{x}", .{ user_text_size, user_data_size });

    virtual_address_space.map(.local, user_text_physical_address, user_text_virtual_address, user_text_size, .{ .write = false, .execute = true, .user = true }) catch @panic("user text");
    virtual_address_space.map(.local, user_data_physical_address, user_data_virtual_address, user_data_size, .{ .write = true, .execute = false, .user = true }) catch @panic("user data");

    const user_stack_allocation = cpu.page_allocator.allocate(0x4000, 0x1000) catch @panic("user stack");
    virtual_address_space.map(.local, user_stack_allocation.address, user_stack_allocation.address.toIdentityMappedVirtualAddress(), user_stack_allocation.size, .{ .write = true, .execute = false, .user = true }) catch @panic("User stack");
    _ = user_stack;

    for (program_headers) |program_header| {
        if (program_header.type == .load) {
            log.debug("Segment: 0x{x}, 0x{x}", .{ program_header.virtual_address, program_header.size_in_memory });
            const aligned_size = lib.alignForward(program_header.size_in_memory, lib.arch.valid_page_sizes[0]);
            const segment_physical_region = cpu.page_allocator.allocate(aligned_size, lib.arch.valid_page_sizes[0]) catch @panic("Segment allocation failed");
            const segment_physical_address = segment_physical_region.address;
            const segment_virtual_address = VirtualAddress(.local).new(program_header.virtual_address);
            const segment_flags = .{
                .execute = program_header.flags.executable,
                .write = program_header.flags.writable,
                .user = true,
            };

            virtual_address_space.map(.local, segment_physical_address, segment_virtual_address, aligned_size, segment_flags) catch @panic("Segment mapping failed user");

            const dst = segment_physical_region.toHigherHalfVirtualAddress().access(u8);
            const src = init_file[program_header.offset..][0..program_header.size_in_memory];
            lib.copy(u8, dst, src);

            paging.switchTo(virtual_address_space, .privileged);

            virtual_address_space.map(.local, segment_physical_address, segment_virtual_address, aligned_size, segment_flags) catch |err| {
                const physical_address = virtual_address_space.translateAddress(segment_virtual_address) catch @panic("cannot be translated");
                log.debug("Translated address: 0x{x}", .{physical_address.value()});
                panic("Segment mapping failed cpu: {}", .{err});
            };

            paging.switchTo(virtual_address_space, .user);
        }
    }

    init_director.virtual_address_space = virtual_address_space;
    init_director.disabled = true;
    init_director_shared.base.disabled = lib.maxInt(u32);
    init_director_shared.disabled_save_area.rdi = 0x20000;
    init_director_shared.disabled_save_area.fs = 0;
    init_director_shared.disabled_save_area.gs = 0;
    init_director_shared.disabled_save_area.rflags = .{
        .IF = true,
    };
    init_director_shared.disabled_save_area.fxsave_area.fcw = 0x037f;
    init_director_shared.disabled_save_area.fxsave_area.mxcsr = 0x00001f80;

    init_director_shared.disabled_save_area.rip = entry_point;
    init_director_shared.disabled_save_area.rsp = user_stack_allocation.address.offset(user_stack_allocation.size).toIdentityMappedVirtualAddress().value();
    init_director_shared.disabled_save_area.cr3 = @bitCast(u64, virtual_address_space.arch.cr3);

    virtual_address_space.mapPageTables() catch |err| privileged.panic("Unable to map page tables: {}", .{err});

    const physical_address = virtual_address_space.translateAddress(VirtualAddress(.local).new(0x200290)) catch @panic("can't translate");
    log.debug("PA: 0x{x}", .{physical_address.value()});

    log.debug("Initialized director", .{});

    return init_director;
}

pub fn initAPIC() void {
    log.debug("Initializing APIC", .{});
    var ia32_apic_base = IA32_APIC_BASE.read();
    const apic_base_physical_address = ia32_apic_base.getAddress();
    comptime {
        assert(lib.arch.valid_page_sizes[0] == 0x1000);
    }
    log.debug("Mapping APIC", .{});
    const apic_base = cpu.virtual_address_space.mapDevice(apic_base_physical_address, lib.arch.valid_page_sizes[0]) catch @panic("mapping apic failed");
    log.debug("Mapped APIC", .{});

    const spurious_vector: u8 = 0xFF;
    apic_base.offset(@enumToInt(APIC.Register.spurious)).access(*volatile u32).* = @as(u32, 0x100) | spurious_vector;

    const tpr = APIC.TaskPriorityRegister{};
    tpr.write();

    const lvt_timer = APIC.LVTTimer{};
    lvt_timer.write();

    ia32_apic_base.global_enable = true;
    ia32_apic_base.write();
    log.debug("APIC enabled", .{});

    APIC.calibrateTimer();
}

extern const text_section_start: *u8;
extern const data_section_start: *u8;

extern const user_text_start: *u8;
extern const user_text_end: *u8;
extern const user_data_start: *u8;
extern const user_data_end: *u8;
