const lib = @import("lib");
const Allocator = lib.Allocator;
const assert = lib.assert;
const log = lib.log;
const bootloader = @import("bootloader");
const privileged = @import("privileged");
const panic = cpu.panic;
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

export var interrupt_stack: [0x1000]u8 align(0x10) = undefined;
export var gdt = GDT{};
export var tss = TSS{};
export var idt = IDT{};
export var user_stack: u64 = 0;
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

const interrupt_kind: u32 = 0;
const interrupt_descriptions: lib.AutoEnumArray(Interrupt, []const u8) = undefined;

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

    const cpuid = lib.arch.x86_64.cpuid;
    if (pcid) {
        if (cpuid(1).ecx & (1 << 17) == 0) @panic("PCID not available");
    }

    {
        // if (cpuid(0x80000007).edx & (1 << 8) == 0) @panic("Invariant TSC not available");
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
    cpu.page_allocator = PageAllocator.fromBSP(bootloader_information);

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

export fn interruptHandler(regs: *const InterruptRegisters, interrupt_number: u8) void {
    _ = interrupt_number;
    _ = regs;
    APIC.lapicWrite(.eoi, 0);
    nextTimer(10);
}

pub const interrupt_handlers = [256]*const fn () callconv(.Naked) noreturn{
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
        \\popq %rbp
        \\popq %rbx
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
            : [user_cr3_mask] "i" (cr3_user_page_table_mask),
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
            const exit_code = @intToEnum(lib.QEMU.ExitCode, arguments[0]);
            log.debug("Exiting QEMU with {s} code", .{@tagName(exit_code)});
            privileged.exitFromQEMU(exit_code);
        },
        .print => {
            const message = @intToPtr([*]const u8, arguments[0])[0..arguments[1]];
            writerStart();
            writer.writeAll(message) catch unreachable;
            writerEnd();
        },
        //else => panic("Unknown syscall: {s}", .{@tagName(number)}),
    }
}

const pcid_bit = 11;
const pcid_mask = 1 << pcid_bit;
const cr3_user_page_table_mask = 1 << @bitOffsetOf(cr3, "address");
const cr3_user_page_table_and_pcid_mask = cr3_user_page_table_mask | pcid_mask;

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

noinline fn resumeExecution(state: *align(16) Registers) noreturn {
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
    while (true) {
        privileged.exitFromQEMU(.success);
    }
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
    defer paging.unmapCapabilitySpace(user_side_pml4_physical_address);
    log.debug("Higher half end", .{});

    // First map vital parts for context switch
    virtual_address_space.arch = .{
        .cr3 = cr3.from_address(cpu_side_pml4_physical_address),
    };

    // Identity map dispatcher
    virtual_address_space.map(.local, init_director_allocation.address, init_director_allocation.address.toIdentityMappedVirtualAddress(), aligned_init_director_size, .{ .write = true, .user = true }) catch @panic("user init director ");
    virtual_address_space.map(.local, init_director_shared_allocation.address, init_director_shared_allocation.address.toIdentityMappedVirtualAddress(), aligned_init_director_shared_size, .{ .write = true, .user = true }) catch @panic("user init director shared");

    const init_director = init_director_allocation.address.toHigherHalfVirtualAddress().access(*CoreDirectorData);
    const init_director_shared = init_director_shared_allocation.address.toHigherHalfVirtualAddress().access(*CoreDirectorShared);
    init_director.shared = &init_director_shared.base;

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

    virtual_address_space.mapPageTables() catch |err| panic("Unable to map page tables: {}", .{err});

    return init_director;
}

var ticks_per_ms: privileged.arch.x86_64.TicksPerMS = undefined;
const local_timer_vector = 0xef;

pub inline fn nextTimer(ms: u32) void {
    APIC.lapicWrite(.lvt_timer, local_timer_vector | (1 << 17));
    APIC.lapicWrite(.timer_initcnt, ticks_per_ms.lapic * ms);
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

    ticks_per_ms = APIC.calibrateTimer();

    nextTimer(1);
}

extern const text_section_start: *u8;
extern const data_section_start: *u8;
extern const user_text_start: *u8;
extern const user_text_end: *u8;
extern const user_data_start: *u8;
extern const user_data_end: *u8;

pub const Spinlock = enum(u8) {
    released = 0,
    acquired = 1,

    pub inline fn acquire(spinlock: *volatile Spinlock) void {
        asm volatile (
            \\0:
            \\xchgb %[value], %[spinlock]
            \\test %[value], %[value]
            \\jz 2f
            // If not acquire, go to spinloop
            \\1:
            \\pause
            \\cmp %[value], %[spinlock]
            // Retry
            \\jne 0b
            \\jmp 1b
            \\2:
            :
            : [spinlock] "*p" (spinlock),
              [value] "r" (Spinlock.acquired),
            : "memory"
        );
    }

    pub inline fn release(spinlock: *volatile Spinlock) void {
        @atomicStore(Spinlock, spinlock, .released, .Release);
    }
};

pub const writer = privileged.E9Writer{ .context = {} };
var writer_lock: Spinlock = .released;

pub inline fn writerStart() void {
    writer_lock.acquire();
}

pub inline fn writerEnd() void {
    writer_lock.release();
}
