const lib = @import("lib");
const assert = lib.assert;
const log = lib.log;
const bootloader = @import("bootloader");
const privileged = @import("privileged");
const x86_64 = privileged.arch.x86_64;
const APIC = x86_64.APIC;
const TSS = x86_64.TSS;
const registers = x86_64.registers;
const cr0 = registers.cr0;
const cr4 = registers.cr4;
const IA32_APIC_BASE = registers.IA32_APIC_BASE;
const IA32_EFER = registers.IA32_EFER;
const IA32_FSTAR = registers.IA32_FSTAR;
const IA32_FMASK = registers.IA32_FMASK;
const IA32_LSTAR = registers.IA32_LSTAR;
const IA32_STAR = registers.IA32_STAR;

const code_64 = @offsetOf(GDT, "code_64");
const data_64 = @offsetOf(GDT, "data_64");
const user_code_64 = @offsetOf(GDT, "user_code_64");
const user_data_64 = @offsetOf(GDT, "user_data_64");
const tss_selector = @offsetOf(GDT, "tss_descriptor");

const cpu = @import("cpu");

export var interrupt_stack: [0x1000]u8 align(0x1000) = undefined;
export var gdt = GDT{};
export var tss = TSS{};
export var idt = IDT{};

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
        : [entry_point] "r" (@import("root").main),
          [stack_len] "i" (cpu.stack.len),
    );

    unreachable;
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

pub fn dummyInterruptHandler() callconv(.Naked) noreturn {
    asm volatile (
        \\cli
        \\hlt
    );
    unreachable;
}

pub fn syscalEntryPoint() callconv(.Naked) void {
    asm volatile (
        \\cli
        \\hlt
    );
    unreachable;
}

pub fn earlyInitialize(bootloader_information: *bootloader.Information) void {
    // Reload allocator function pointers because we probably come from 32-bit code
    bootloader_information.page_allocator.callbacks.allocate = bootloader.Information.pageAllocate;
    bootloader_information.heap.allocator.callbacks.allocate = bootloader.Information.heapAllocate;
    x86_64.paging.registerPhysicalAllocator(&bootloader_information.page_allocator);
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

    tss.rsp[0] = @ptrToInt(&interrupt_stack);
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

    APIC.init();

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

    IA32_LSTAR.write(@ptrToInt(&syscalEntryPoint));
    // TODO: figure out what this does
    IA32_FMASK.write(@truncate(u22, ~@as(u64, 1 << 1)));

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
}

fn kernelStartup(bootloader_information: *bootloader.Information) noreturn {
    if (bsp) {
        const init_director = spawnBSPInit(bootloader_information);
        _ = init_director;
        @panic("TODO: bsp");
    } else {
        @panic("APP");
    }

    @panic("TODO: kernel startup");
}

pub const CoreDirectorData = extern struct {
    dispatcher_handle: privileged.arch.VirtualAddress(.local),
    disabled: bool,
    //cspace: CTE,
    vspace: usize,
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
        privileged.arch.paging.context_switch(core_director_data.vspace);
        context_switch_counter += 1;
        // TODO: implement LDT
    }

    var context_switch_counter: usize = 0;
};

fn spawnBSPInit(bootloader_information: *bootloader.Information) *CoreDirectorData {
    _ = bootloader_information;
    // const init_file = bootloader_information.fetchFileByType(.init) orelse @panic("No init module found");
    // _ = init_file;
    // assert(bsp);
    privileged.exitFromQEMU(true);
}
