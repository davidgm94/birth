const bootloader = @import("bootloader");
const cpu = @import("cpu");
const lib = @import("lib");
const privileged = @import("privileged");
const rise = @import("rise");

const Allocator = lib.Allocator;
const assert = lib.assert;
const ELF = lib.ELF(64);
const log = lib.log.scoped(.INIT);
const PhysicalAddress = lib.PhysicalAddress;
const PhysicalMemoryRegion = lib.PhysicalMemoryRegion;
const VirtualAddress = lib.VirtualAddress;
const VirtualMemoryRegion = lib.VirtualMemoryRegion;

const panic = cpu.panic;
const x86_64 = cpu.arch.current;

const paging = privileged.arch.paging;

const APIC = privileged.arch.x86_64.APIC;
const cr0 = privileged.arch.x86_64.registers.cr0;
const cr3 = privileged.arch.x86_64.registers.cr3;
const cr4 = privileged.arch.x86_64.registers.cr4;
const XCR0 = privileged.arch.x86_64.registers.XCR0;
const IA32_APIC_BASE = privileged.arch.x86_64.registers.IA32_APIC_BASE;
const IA32_EFER = privileged.arch.x86_64.registers.IA32_EFER;
const IA32_FS_BASE = privileged.arch.x86_64.registers.IA32_FS_BASE;
const IA32_FSTAR = privileged.arch.x86_64.registers.IA32_FSTAR;
const IA32_FMASK = privileged.arch.x86_64.registers.IA32_FMASK;
const IA32_LSTAR = privileged.arch.x86_64.registers.IA32_LSTAR;
const IA32_STAR = privileged.arch.x86_64.registers.IA32_STAR;

const user_scheduler_memory_start_virtual_address = VirtualAddress.new(0x200_000);
const user_scheduler_virtual_address = user_scheduler_memory_start_virtual_address;

pub fn entryPoint() callconv(.Naked) noreturn {
    asm volatile (
        \\lea stack(%rip), %rsp
        \\add %[stack_len], %rsp
        \\pushq $0
        \\mov %rsp, %rbp
        \\jmp *%[main]
        :
        : [stack_len] "i" (cpu.stack.len),
          [main] "{rax}" (&main),
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

noinline fn main(bootloader_information: *bootloader.Information) callconv(.C) noreturn {
    log.info("Initializing...\n\n\t[BUILD MODE] {s}\n\t[BOOTLOADER] {s}\n\t[BOOT PROTOCOL] {s}\n", .{ @tagName(lib.build_mode), @tagName(bootloader_information.bootloader), @tagName(bootloader_information.protocol) });
    archInitialize(bootloader_information) catch |err| {
        cpu.panicWithStackTrace(@errorReturnTrace(), "Failed to initialize CPU: {}", .{err});
    };
}

fn archInitialize(bootloader_information: *bootloader.Information) !noreturn {
    // bootloader_information.draw_context.clearScreen(0xffff7f50);
    // Do an integrity check so that the bootloader information is in perfect state and there is no weird memory behavior.
    // This is mainly due to the transition from a 32-bit bootloader to a 64-bit CPU driver in the x86-64 architecture.
    try bootloader_information.checkIntegrity();
    // Informing the bootloader information struct that we have reached the CPU driver and any bootloader
    // functionality is not available anymore
    bootloader_information.stage = .cpu;
    // Check that the bootloader has loaded some files as the CPU driver needs them to go forward
    cpu.bundle = bootloader_information.getSlice(.bundle);
    if (cpu.bundle.len == 0) return InitializationError.no_files;
    cpu.bundle_files = bootloader_information.getSlice(.file_list);
    if (cpu.bundle_files.len == 0) return InitializationError.no_files;

    const cpuid = lib.arch.x86_64.cpuid;
    if (x86_64.pcid) {
        if (cpuid(1).ecx & (1 << 17) == 0) return InitializationError.feature_requested_and_not_available;
    }

    if (x86_64.invariant_tsc) {
        if (cpuid(0x80000007).edx & (1 << 8) == 0) return InitializationError.feature_requested_and_not_available;
    }

    // Initialize GDT
    const gdt_descriptor = x86_64.GDT.Descriptor{
        .limit = @sizeOf(x86_64.GDT) - 1,
        .address = @intFromPtr(&gdt),
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
          [ds] "i" (x86_64.data_64),
          [cs] "i" (x86_64.code_64),
        : "memory"
    );

    const tss_address = @intFromPtr(&tss);
    gdt.tss_descriptor = .{
        .limit_low = @as(u16, @truncate(@sizeOf(x86_64.TSS))),
        .base_low = @as(u16, @truncate(tss_address)),
        .base_mid_low = @as(u8, @truncate(tss_address >> 16)),
        .access = .{
            .type = .tss_available,
            .dpl = 0,
            .present = true,
        },
        .attributes = .{
            .limit = @as(u4, @truncate(@sizeOf(x86_64.TSS) >> 16)),
            .available_for_system_software = false,
            .granularity = false,
        },
        .base_mid_high = @as(u8, @truncate(tss_address >> 24)),
        .base_high = @as(u32, @truncate(tss_address >> 32)),
    };

    tss.rsp[0] = @intFromPtr(&interrupt_stack) + interrupt_stack.len;
    asm volatile (
        \\ltr %[tss_selector]
        :
        : [tss_selector] "r" (@as(u16, x86_64.tss_selector)),
        : "memory"
    );

    // Initialize IDT

    for (&idt.descriptors, interrupt_handlers, 0..) |*descriptor, interrupt_handler, i| {
        const interrupt_address = @intFromPtr(interrupt_handler);
        descriptor.* = .{
            .offset_low = @as(u16, @truncate(interrupt_address)),
            .segment_selector = x86_64.code_64,
            .flags = .{
                .ist = 0,
                .type = if (i < 32) .trap_gate else .interrupt_gate, // TODO: I think this is not correct
                .dpl = 0,
                .present = true,
            },
            .offset_mid = @as(u16, @truncate(interrupt_address >> 16)),
            .offset_high = @as(u32, @truncate(interrupt_address >> 32)),
        };
    }

    const idt_descriptor = x86_64.IDT.Descriptor{
        .limit = @sizeOf(x86_64.IDT) - 1,
        .address = @intFromPtr(&idt),
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

    const star = IA32_STAR{
        .kernel_cs = x86_64.code_64,
        .user_cs_anchor = x86_64.data_64,
    };

    comptime {
        assert(x86_64.data_64 == star.kernel_cs + 8);
        assert(star.user_cs_anchor == x86_64.user_data_64 - 8);
        assert(star.user_cs_anchor == x86_64.user_code_64 - 16);
    }

    star.write();

    IA32_LSTAR.write(@intFromPtr(&cpu.arch.x86_64.syscall.entryPoint));
    const syscall_mask = privileged.arch.x86_64.registers.syscall_mask;
    IA32_FMASK.write(syscall_mask);

    // Enable syscall extensions
    var efer = IA32_EFER.read();
    efer.SCE = true;
    efer.write();

    // TODO: AVX

    const avx_xsave_cpuid = cpuid(1);
    const avx_support = avx_xsave_cpuid.ecx & (1 << 28) != 0;
    const xsave_support = avx_xsave_cpuid.ecx & (1 << 26) != 0;
    const avx2_support = cpuid(7).ebx & (1 << 5) != 0;
    log.debug("AVX: {}. AVX2: {}. XSAVE: {}. Can't enable them yet", .{ avx_support, avx2_support, xsave_support });

    comptime {
        assert(lib.arch.valid_page_sizes[0] == 0x1000);
    }

    var my_cr4 = cr4.read();
    my_cr4.OSFXSR = true;
    my_cr4.OSXMMEXCPT = true;
    //my_cr4.OSXSAVE = true;
    my_cr4.page_global_enable = true;
    my_cr4.performance_monitoring_counter_enable = true;
    my_cr4.write();

    var my_cr0 = cr0.read();
    my_cr0.monitor_coprocessor = true;
    my_cr0.emulation = false;
    my_cr0.numeric_error = true;
    my_cr0.task_switched = false;
    my_cr0.write();

    // The bootloader already mapped APIC, so it's not necessary to map it here
    var ia32_apic_base = IA32_APIC_BASE.read();
    cpu.bsp = ia32_apic_base.bsp;
    ia32_apic_base.global_enable = true;

    const spurious_vector: u8 = 0xFF;
    APIC.write(.spurious, @as(u32, 0x100) | spurious_vector);

    const tpr = APIC.TaskPriorityRegister{};
    tpr.write();

    const lvt_timer = APIC.LVTTimer{};
    lvt_timer.write();

    ia32_apic_base.write();

    x86_64.ticks_per_ms = APIC.calibrateTimer();

    cpu.core_id = APIC.read(.id);

    asm volatile (
        \\fninit
        // TODO: figure out why this crashes with KVM
        //\\ldmxcsr %[mxcsr]
        :: //[mxcsr] "m" (@as(u32, 0x1f80)),
        : "memory");

    // Write user TLS base address
    IA32_FS_BASE.write(user_scheduler_virtual_address.value());

    // TODO: configure PAT

    try initialize(bootloader_information);
}

fn initialize(bootloader_information: *bootloader.Information) !noreturn {
    const memory_map_entries = bootloader_information.getMemoryMapEntries();
    const page_counters = bootloader_information.getPageCounters();

    var free_size: usize = 0;
    var free_region_count: usize = 0;

    for (memory_map_entries, page_counters) |mmap_entry, page_counter| {
        if (mmap_entry.type == .usable) {
            const free_region = mmap_entry.getFreeRegion(page_counter);
            free_size += free_region.size;
            free_region_count += @intFromBool(free_region.size > 0);
        }
    }

    const total_to_allocate = @sizeOf(cpu.Driver) + @sizeOf(cpu.capabilities.Root) + lib.arch.valid_page_sizes[0];

    const total_physical: struct {
        region: PhysicalMemoryRegion,
        free_size: u64,
        index: usize,
    } = for (memory_map_entries, page_counters, 0..) |mmap_entry, page_counter, index| {
        if (mmap_entry.type == .usable) {
            const free_region = mmap_entry.getFreeRegion(page_counter);
            if (free_region.size >= total_to_allocate) {
                break .{
                    .region = PhysicalMemoryRegion.new(.{
                        .address = free_region.address,
                        .size = total_to_allocate,
                    }),
                    .free_size = free_region.size - total_to_allocate,
                    .index = index,
                };
            }
        }
    } else @panic("Total physical region not found");

    var offset: usize = 0;

    cpu.driver = total_physical.region.offset(offset).address.toHigherHalfVirtualAddress().access(*align(lib.arch.valid_page_sizes[0]) cpu.Driver);
    offset += @sizeOf(cpu.Driver);

    const root_capability = total_physical.region.offset(offset).address.toHigherHalfVirtualAddress().access(*cpu.capabilities.Root);
    offset += @sizeOf(cpu.capabilities.Root);

    var heap_offset: usize = 0;
    const heap_region = total_physical.region.offset(offset);
    assert(heap_region.size == lib.arch.valid_page_sizes[0]);
    const host_free_ram = heap_region.offset(heap_offset).address.toHigherHalfVirtualAddress().access(*cpu.capabilities.RAM.Region);
    host_free_ram.* = .{
        .region = PhysicalMemoryRegion.new(.{
            .address = total_physical.region.offset(total_to_allocate).address,
            .size = total_physical.free_size,
        }),
    };
    heap_offset += @sizeOf(cpu.capabilities.RAM.Region);
    const privileged_cpu_memory = heap_region.offset(heap_offset).address.toHigherHalfVirtualAddress().access(*cpu.capabilities.RAM.Region);
    privileged_cpu_memory.* = .{
        .region = total_physical.region,
    };

    heap_offset += @sizeOf(cpu.capabilities.RAM);

    var previous_free_ram = host_free_ram;
    for (memory_map_entries, page_counters, 0..) |memory_map_entry, page_counter, index| {
        if (index == total_physical.index) continue;

        if (memory_map_entry.type == .usable) {
            const region = memory_map_entry.getFreeRegion(page_counter);
            if (region.size > 0) {
                const new_free_ram = heap_region.offset(heap_offset).address.toHigherHalfVirtualAddress().access(*cpu.capabilities.RAM.Region);
                heap_offset += @sizeOf(cpu.capabilities.RAM.Region);
                new_free_ram.* = .{
                    .region = region,
                };
                previous_free_ram.next = new_free_ram;
                previous_free_ram = new_free_ram;
            }
        }
    }

    root_capability.* = .{
        .static = .{
            .cpu = true,
            .boot = true,
            .process = true,
        },
        .dynamic = .{
            .io = .{
                .debug = true,
            },
            .ram = .{
                .lists = blk: {
                    var lists = [1]?*cpu.capabilities.RAM.Region{null} ** lib.arch.reverse_valid_page_sizes.len;
                    var free_ram_iterator: ?*cpu.capabilities.RAM.Region = host_free_ram;
                    while (free_ram_iterator) |free_ram| {
                        comptime assert(lib.arch.reverse_valid_page_sizes.len == 3);
                        const next = free_ram.next;

                        if (free_ram.region.size >= lib.arch.reverse_valid_page_sizes[0]) {
                            const previous_first = lists[0];
                            lists[0] = free_ram;
                            free_ram.next = previous_first;
                        } else if (free_ram.region.size >= lib.arch.reverse_valid_page_sizes[1]) {
                            const previous_first = lists[1];
                            lists[1] = free_ram;
                            free_ram.next = previous_first;
                        } else if (free_ram.region.size >= lib.arch.reverse_valid_page_sizes[2]) {
                            const previous_first = lists[2];
                            lists[2] = free_ram;
                            free_ram.next = previous_first;
                        } else unreachable;

                        free_ram_iterator = next;
                    }

                    break :blk lists;
                },
            },
            .cpu_memory = .{
                .flags = .{
                    .allocate = true,
                },
            },
            .page_table = .{},
        },
        .scheduler = .{
            .memory = undefined,
        },
        .heap = cpu.capabilities.Root.Heap.new(heap_region, heap_offset),
    };

    cpu.driver.* = .{
        .valid = true,
        .init_root_capability = .{
            .value = root_capability,
        },
    };

    switch (cpu.bsp) {
        true => {
            const init_module_descriptor = try bootloader_information.getFileDescriptor("init");
            try spawnInitBSP(init_module_descriptor.content, bootloader_information.cpu_page_tables);
        },
        false => @panic("Implement APP"),
    }
}

export var interrupt_stack: [0x1000]u8 align(lib.arch.stack_alignment) = undefined;
export var gdt = x86_64.GDT{};
export var tss = x86_64.TSS{};
export var idt = x86_64.IDT{};
export var user_stack: u64 = 0;

comptime {
    assert(rise.arch.user_code_selector == x86_64.user_code_selector);
    assert(rise.arch.user_data_selector == x86_64.user_data_selector);
}

pub fn InterruptHandler(comptime interrupt_number: u64, comptime has_error_code: bool) fn () callconv(.Naked) noreturn {
    return struct {
        fn handler() callconv(.Naked) noreturn {
            asm volatile (
                \\endbr64
                ::: "memory");

            if (x86_64.smap) {
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
                \\push %rbx
                \\push %rbp
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
const interrupt_handlers = [256]*const fn () callconv(.Naked) noreturn{
    InterruptHandler(@intFromEnum(Interrupt.DE), false),
    InterruptHandler(@intFromEnum(Interrupt.DB), false),
    InterruptHandler(@intFromEnum(Interrupt.NMI), false),
    InterruptHandler(@intFromEnum(Interrupt.BP), false),
    InterruptHandler(@intFromEnum(Interrupt.OF), false),
    InterruptHandler(@intFromEnum(Interrupt.BR), false),
    InterruptHandler(@intFromEnum(Interrupt.UD), false),
    InterruptHandler(@intFromEnum(Interrupt.NM), false),
    InterruptHandler(@intFromEnum(Interrupt.DF), true),
    InterruptHandler(@intFromEnum(Interrupt.CSO), false),
    InterruptHandler(@intFromEnum(Interrupt.TS), true),
    InterruptHandler(@intFromEnum(Interrupt.NP), true),
    InterruptHandler(@intFromEnum(Interrupt.SS), true),
    InterruptHandler(@intFromEnum(Interrupt.GP), true),
    InterruptHandler(@intFromEnum(Interrupt.PF), true),
    InterruptHandler(0x0f, false),
    InterruptHandler(@intFromEnum(Interrupt.MF), false),
    InterruptHandler(@intFromEnum(Interrupt.AC), true),
    InterruptHandler(@intFromEnum(Interrupt.MC), false),
    InterruptHandler(@intFromEnum(Interrupt.XM), false),
    InterruptHandler(@intFromEnum(Interrupt.VE), false),
    InterruptHandler(@intFromEnum(Interrupt.CP), true),
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
                const misalignment = lib.alignForward(usize, heap.virtual_memory_region.address.value(), alignment) - heap.virtual_memory_region.address.value();
                _ = heap.virtual_memory_region.takeSlice(misalignment);
            }

            return heap.virtual_memory_region.takeByteSlice(size);
        }
    };

    pub fn createPageAligned(allocator: *BSPEarlyAllocator, comptime T: type) AllocatorError!*align(lib.arch.valid_page_sizes[0]) T {
        return @as(*align(lib.arch.valid_page_sizes[0]) T, @ptrCast(try allocator.allocateBytes(@sizeOf(T), lib.arch.valid_page_sizes[0])));
    }

    pub fn allocateBytes(allocator: *BSPEarlyAllocator, size: u64, alignment: u64) AllocatorError![]align(lib.arch.valid_page_sizes[0]) u8 {
        if (!lib.isAligned(size, lib.arch.valid_page_sizes[0])) return AllocatorError.bad_alignment;
        if (allocator.offset + size > allocator.size) return AllocatorError.out_of_memory;

        // TODO: don't trash memory
        if (!lib.isAligned(allocator.base.offset(allocator.offset).value(), alignment)) {
            const aligned = lib.alignForward(usize, allocator.base.offset(allocator.offset).value(), alignment);
            allocator.offset += aligned - allocator.base.offset(allocator.offset).value();
        }

        const physical_address = allocator.base.offset(allocator.offset);
        allocator.offset += size;
        const slice = physical_address.toHigherHalfVirtualAddress().access([*]align(lib.arch.valid_page_sizes[0]) u8)[0..size];
        @memset(slice, 0);

        return slice;
    }

    pub fn callbackAllocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
        const early_allocator = @fieldParentPtr(BSPEarlyAllocator, "allocator", allocator);
        if (alignment == lib.arch.valid_page_sizes[0] or size % lib.arch.valid_page_sizes[0] == 0) {
            const result = early_allocator.allocateBytes(size, alignment) catch return Allocator.Allocate.Error.OutOfMemory;
            return .{
                .address = @intFromPtr(result.ptr),
                .size = result.len,
            };
        } else if (alignment > lib.arch.valid_page_sizes[0]) {
            @panic("WTF");
        } else {
            assert(size < lib.arch.valid_page_sizes[0]);
            const heap_entry_allocation = early_allocator.allocateBytes(lib.arch.valid_page_sizes[0], lib.arch.valid_page_sizes[0]) catch return Allocator.Allocate.Error.OutOfMemory;
            const heap_entry_region = VirtualMemoryRegion.fromByteSlice(.{
                .slice = heap_entry_allocation,
            });
            const heap_entry = try early_allocator.addHeapRegion(heap_entry_region);
            const result = try heap_entry.allocateBytes(size, alignment);
            return .{
                .address = @intFromPtr(result.ptr),
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

const half_page_table_entry_count = @divExact(paging.page_table_entry_count, 2);

fn spawnInitBSP(init_file: []const u8, cpu_page_tables: paging.CPUPageTables) !noreturn {
    const spawn_init = try spawnInitCommon(cpu_page_tables);
    const init_scheduler = spawn_init.scheduler;
    const page_table_regions = spawn_init.page_table_regions;

    // TODO: make this the right one
    const address_space = page_table_regions.getAddressSpace();
    const init_elf = try ELF.Parser.init(init_file);
    const entry_point = init_elf.getEntryPoint();
    const program_headers = init_elf.getProgramHeaders();
    const scheduler_common = init_scheduler.common;

    for (program_headers) |program_header| {
        if (program_header.type == .load) {
            const aligned_size = lib.alignForward(usize, program_header.size_in_memory, lib.arch.valid_page_sizes[0]);
            const segment_virtual_address = VirtualAddress.new(program_header.virtual_address);
            const indexed_virtual_address = @as(paging.IndexedVirtualAddress, @bitCast(program_header.virtual_address));
            _ = indexed_virtual_address;
            const segment_flags = .{
                .execute_disable = !program_header.flags.executable,
                .write = program_header.flags.writable,
                .user = true,
            };

            const segment_physical_region = try cpu.driver.getRootCapability().allocatePages(aligned_size);
            try page_table_regions.map(segment_virtual_address, segment_physical_region.address, segment_physical_region.size, segment_flags);

            const src = init_file[program_header.offset..][0..program_header.size_in_file];
            const dst = segment_physical_region.toHigherHalfVirtualAddress().access(u8)[0..program_header.size_in_file];
            @memcpy(dst, src);
        }
    }

    // Once all page tables are set up, copy lower half of the address space to the cpu page table
    const cpu_pml4 = page_table_regions.getCpuPML4();
    const user_pml4 = page_table_regions.getUserPML4();
    @memcpy(cpu_pml4[0..half_page_table_entry_count], user_pml4[0..half_page_table_entry_count]);

    cpu.user_scheduler = init_scheduler;
    address_space.cr3.write();

    scheduler_common.self = scheduler_common;

    const scheduler_common_arch = scheduler_common.architectureSpecific();

    // Set arguments

    // First argument
    scheduler_common_arch.disabled_save_area.registers.rdi = user_scheduler_virtual_address.value();
    // Second argument
    const is_init = true;
    scheduler_common_arch.disabled_save_area.registers.rsi = @intFromBool(is_init);

    scheduler_common_arch.disabled_save_area.registers.rip = entry_point; // Set entry point
    scheduler_common_arch.disabled_save_area.registers.rsp = user_scheduler_virtual_address.offset(@offsetOf(rise.UserScheduler, "setup_stack")).value() + scheduler_common_arch.generic.setup_stack.len;
    scheduler_common.setup_stack_lock.value = true;
    scheduler_common_arch.disabled_save_area.registers.rflags = .{ .IF = true }; // Set RFLAGS

    scheduler_common_arch.disabled_save_area.fpu.fcw = 0x037f; // Set FPU
    scheduler_common_arch.disabled_save_area.fpu.mxcsr = 0x1f80;

    scheduler_common_arch.disabled_save_area.contextSwitch();
}

const UserMemory = extern struct {
    root: PhysicalMemoryRegion,
    pdpt: PhysicalMemoryRegion,
    pdt: PhysicalMemoryRegion,
    pt: PhysicalMemoryRegion,
};

const PageTableRegions = extern struct {
    regions: [region_count]PhysicalMemoryRegion,
    total: PhysicalMemoryRegion,
    base_virtual_address: VirtualAddress,

    fn mapQuick(page_table_regions: PageTableRegions, virtual_address: VirtualAddress, physical_address: PhysicalAddress, size: usize, flags: paging.MemoryFlags) void {
        const ptes = page_table_regions.getPageTables(.{ .index = .pt });
        // log.debug("PTE base: 0x{x}", .{@ptrToInt(ptes.ptr)});
        assert(lib.isAligned(size, lib.arch.valid_page_sizes[0]));
        const indexed = @as(paging.IndexedVirtualAddress, @bitCast(virtual_address.value()));
        const base_indexed = @as(paging.IndexedVirtualAddress, @bitCast(page_table_regions.base_virtual_address.value()));
        const physical_base = physical_address.value();
        var physical_iterator = physical_base;
        const physical_top = physical_base + size;
        const pd_offset_index = indexed.PD - base_indexed.PD;
        // log.debug("PD index: {}. PD offset index: {}", .{ indexed.PD, pd_offset_index });
        var index = @as(usize, pd_offset_index) * paging.page_table_entry_count + indexed.PT;
        // log.debug("Virtual address: 0x{x}. Size: 0x{x}. Index: {}. PD: {}. PT: {}", .{ virtual_address.value(), size, index, indexed.PD, indexed.PT });

        while (physical_iterator < physical_top) : ({
            physical_iterator += lib.arch.valid_page_sizes[0];
            index += 1;
        }) {
            ptes[index] = paging.getPageEntry(paging.PTE, physical_iterator, flags);
        }
    }

    fn map(page_table_regions: PageTableRegions, virtual_address: VirtualAddress, physical_address: PhysicalAddress, size: usize, flags: paging.MemoryFlags) !void {
        // log.debug("Mapping 0x{x} -> 0x{x} for 0x{x} bytes", .{ virtual_address.value(), physical_address.value(), size });
        assert(page_table_regions.regions[@intFromEnum(Index.pml4)].size == 2 * lib.arch.valid_page_sizes[0]);
        assert(page_table_regions.regions[@intFromEnum(Index.pdp)].size == lib.arch.valid_page_sizes[0]);
        assert(page_table_regions.regions[@intFromEnum(Index.pd)].size == lib.arch.valid_page_sizes[0]);

        page_table_regions.mapQuick(virtual_address, physical_address, size, flags);

        const address_space = page_table_regions.getAddressSpace();
        const virtual_address_top = virtual_address.offset(size).value();
        var index: usize = 0;

        while (virtual_address.offset(index * lib.arch.valid_page_sizes[0]).value() < virtual_address_top) : (index += 1) {
            const offset = index * lib.arch.valid_page_sizes[0];
            const expected_pa = physical_address.offset(offset);
            const va = virtual_address.offset(offset);

            const translated_physical_address = address_space.translateAddress(va, flags) catch |err| {
                panic("Mapping of 0x{x} failed: {}", .{ va.value(), err });
            };

            if (translated_physical_address.value() != expected_pa.value()) {
                @panic("Mapping failed");
            }
        }
    }

    const region_count = lib.enumCount(Index);
    const Index = enum(u2) {
        pml4,
        pdp,
        pd,
        pt,
    };

    const sizes = blk: {
        const shifter = lib.arch.page_shifter(lib.arch.valid_page_sizes[0]);
        var result: [region_count]comptime_int = undefined;

        for (&result, entry_count_array) |*size, entry_count| {
            size.* = @divExact(entry_count, paging.page_table_entry_count) << shifter;
        }

        break :blk result;
    };

    const total_size = blk: {
        var result: comptime_int = 0;

        for (sizes) |size| {
            result += size;
        }

        break :blk result;
    };

    const entry_count_array = blk: {
        var result: [region_count]comptime_int = undefined;

        result[@intFromEnum(Index.pml4)] = 2 * paging.page_table_entry_count;
        result[@intFromEnum(Index.pdp)] = init_vas_pdpe_count;
        result[@intFromEnum(Index.pd)] = init_vas_pde_count;
        result[@intFromEnum(Index.pt)] = init_vas_pte_count;

        break :blk result;
    };

    const EntryType = blk: {
        var result: [region_count]type = undefined;
        result[@intFromEnum(Index.pml4)] = paging.PML4TE;
        result[@intFromEnum(Index.pdp)] = paging.PDPTE;
        result[@intFromEnum(Index.pd)] = paging.PDTE;
        result[@intFromEnum(Index.pt)] = paging.PTE;
        break :blk result;
    };

    const init_vas_size = 128 * lib.mb;
    const init_vas_page_count = @divExact(init_vas_size, lib.arch.valid_page_sizes[0]);

    const init_vas_pte_count = init_vas_page_count;
    const init_vas_pde_count = lib.alignForward(usize, @divExact(init_vas_pte_count, paging.page_table_entry_count), paging.page_table_entry_count);
    const init_vas_pdpe_count = lib.alignForward(usize, @divExact(init_vas_pde_count, paging.page_table_entry_count), paging.page_table_entry_count);

    const AccessOptions = packed struct {
        index: Index,
        user: bool = true,
    };

    pub inline fn getPhysicalRegion(regions: PageTableRegions, comptime options: AccessOptions) PhysicalMemoryRegion {
        const index = @intFromEnum(options.index);
        const result = regions.regions[index].offset(switch (index) {
            0 => switch (options.user) {
                true => paging.page_table_size,
                false => 0,
            },
            else => 0,
        });

        return switch (index) {
            0 => PhysicalMemoryRegion.new(.{ .address = result.address, .size = paging.page_table_size }),
            else => result,
        };
    }

    pub inline fn getPageTables(regions: PageTableRegions, comptime options: AccessOptions) []EntryType[@intFromEnum(options.index)] {
        return regions.getPhysicalRegion(options).toHigherHalfVirtualAddress().access(EntryType[@intFromEnum(options.index)]);
    }

    pub inline fn getAddressSpace(regions: PageTableRegions) paging.Specific {
        const address_space = paging.Specific{ .cr3 = cr3.fromAddress(regions.getPhysicalRegion(.{ .index = .pml4, .user = true }).address) };
        return address_space;
    }

    pub inline fn getPrivilegedAddressSpace(regions: PageTableRegions) paging.Specific {
        const address_space = paging.Specific{ .cr3 = cr3.fromAddress(regions.getPhysicalRegion(.{ .index = .pml4, .user = false }).address) };
        return address_space;
    }

    pub inline fn getCpuPML4(regions: PageTableRegions) *paging.PML4Table {
        return regions.getPageTables(.{ .index = .pml4, .user = false })[0..paging.page_table_entry_count];
    }

    pub inline fn getUserPML4(regions: PageTableRegions) *paging.PML4Table {
        return regions.getPageTables(.{ .index = .pml4, .user = true })[0..paging.page_table_entry_count];
    }
};

const SpawnInitCommonResult = extern struct {
    page_table_regions: PageTableRegions,
    scheduler: *cpu.UserScheduler,
};

const scheduler_memory_size = 1 << 19;
const dispatch_count = x86_64.IDT.entry_count;
var once: bool = false;

fn spawnInitCommon(cpu_page_tables: paging.CPUPageTables) !SpawnInitCommonResult {
    assert(!once);
    once = true;
    // TODO: delete in the future
    assert(cpu.bsp);
    cpu.driver.valid = true;

    const allocation: extern struct {
        page_table_regions: PageTableRegions,
        cpu_page_table_physical_region: PhysicalMemoryRegion,
    } = blk: {
        const page_table_regions_total_size = PageTableRegions.total_size;
        const cpu_page_table_size = (paging.Level.count - 1) * paging.page_table_size;
        const allocation_size = page_table_regions_total_size + cpu_page_table_size;
        const allocation_alignment = 2 * paging.page_table_alignment;
        const total_region = try cpu.driver.getRootCapability().allocatePageCustomAlignment(allocation_size, allocation_alignment);
        //log.debug("Total region: (0x{x}, 0x{x})", .{ total_region.address.value(), total_region.top().value() });
        var region_slicer = total_region;
        var page_table_regions = PageTableRegions{
            .regions = undefined,
            .total = total_region,
            .base_virtual_address = user_scheduler_virtual_address,
        };

        inline for (&page_table_regions.regions, 0..) |*region, index| {
            region.* = region_slicer.takeSlice(PageTableRegions.sizes[index]);
        }

        assert(lib.isAligned(page_table_regions.regions[0].address.value(), 2 * paging.page_table_alignment));

        assert(region_slicer.size == cpu_page_table_size);

        const cpu_page_table_physical_region = region_slicer;

        break :blk .{
            .page_table_regions = page_table_regions,
            .cpu_page_table_physical_region = cpu_page_table_physical_region,
        };
    };

    const page_table_regions = allocation.page_table_regions;
    const cpu_page_table_physical_region = allocation.cpu_page_table_physical_region;

    const indexed_start = @as(paging.IndexedVirtualAddress, @bitCast(user_scheduler_virtual_address.value()));
    const indexed_end = @as(paging.IndexedVirtualAddress, @bitCast(user_scheduler_virtual_address.offset(PageTableRegions.init_vas_size).value()));
    // log.debug("Indexed start: {}", .{indexed_start});
    // log.debug("Indexed end: {}", .{indexed_end});
    page_table_regions.getPageTables(.{
        .index = .pml4,
        .user = true,
    })[indexed_start.PML4] = .{
        .present = true,
        .write = true,
        .user = true,
        .address = paging.packAddress(paging.PML4TE, page_table_regions.getPhysicalRegion(.{ .index = .pdp }).address.value()),
    };

    page_table_regions.getPageTables(.{ .index = .pdp })[indexed_start.PDP] = .{
        .present = true,
        .write = true,
        .user = true,
        .address = paging.packAddress(paging.PDPTE, page_table_regions.getPhysicalRegion(.{ .index = .pd }).address.value()),
    };

    const pdes = page_table_regions.getPageTables(.{ .index = .pd });
    // log.debug("PDE count: {}", .{pdes.len});
    //log.debug("PTE base: 0x{x}. PTE count: {}", .{ page_table_regions.get(.{ .index = .pt }).address.value(), page_table_regions.getPageTables(.{ .index = .pt }).len });

    for (pdes[indexed_start.PD .. indexed_start.PD + indexed_end.PD], 0..) |*pde, pde_offset| {
        const pte_index = paging.page_table_entry_count * pde_offset;
        const pte_offset = pte_index * paging.page_table_entry_size;
        const pte_address = page_table_regions.getPhysicalRegion(.{ .index = .pt }).offset(pte_offset).address.value();
        // log.debug("Linking PDE[{}] 0x{x} with PTE base address: 0x{x} (pte index: {}. pte offset: 0x{x})", .{ pde_offset, @ptrToInt(pde), pte_address, pte_index, pte_offset });
        pde.* = paging.PDTE{
            .present = true,
            .write = true,
            .user = true,
            .address = paging.packAddress(paging.PDTE, pte_address),
        };
    }

    const scheduler_memory_physical_region = try cpu.driver.getRootCapability().allocatePages(scheduler_memory_size);
    const scheduler_memory_map_flags = .{
        .present = true,
        .write = true,
        .user = true,
        .execute_disable = true,
    };

    try page_table_regions.map(user_scheduler_memory_start_virtual_address, scheduler_memory_physical_region.address, scheduler_memory_physical_region.size, scheduler_memory_map_flags);

    const root_page_tables = [2]PhysicalMemoryRegion{
        page_table_regions.getPhysicalRegion(.{ .index = .pml4, .user = false }),
        page_table_regions.getPhysicalRegion(.{ .index = .pml4, .user = true }),
    };
    // log.debug("Root page tables: {any}", .{root_page_tables});
    assert(root_page_tables[0].size == lib.arch.valid_page_sizes[0]);

    // Map CPU driver into the CPU page table
    var cpu_page_table_physical_region_iterator = cpu_page_table_physical_region;
    // log.debug("CPU page table physical region: 0x{x} - 0x{x}", .{ cpu_page_table_physical_region.address.value(), cpu_page_table_physical_region.top().value() });

    const cpu_pte_count = paging.page_table_entry_count - paging.CPUPageTables.left_ptables;
    const cpu_ptes = cpu_page_tables.p_table.toHigherHalfVirtualAddress().access(*paging.PTable)[0..cpu_pte_count];
    const user_mapped_cpu_pte_offset = (paging.Level.count - 2) * paging.page_table_size;
    // log.debug("[OFFSET] 0x{x}", .{user_mapped_cpu_pte_offset});
    const user_mapped_cpu_ptes = cpu_page_table_physical_region.offset(user_mapped_cpu_pte_offset).toHigherHalfVirtualAddress().access(paging.PTE)[0..cpu_pte_count];
    @memcpy(user_mapped_cpu_ptes, cpu_ptes);

    const user_root_page_table_region = root_page_tables[1];
    const RootPageTableEntryType = paging.EntryTypeMap(lib.arch.valid_page_sizes[1])[@intFromEnum(x86_64.root_page_table_entry)];
    user_root_page_table_region.toHigherHalfVirtualAddress().access(paging.PML4TE)[paging.CPUPageTables.pml4_index] = paging.PML4TE{
        .present = true,
        .write = true,
        .execute_disable = false,
        .address = paging.packAddress(RootPageTableEntryType, cpu_page_table_physical_region.offset(0).address.value()),
    };

    const current_address_space = paging.Specific{ .cr3 = cr3.read() };
    const src_half = (try current_address_space.getPML4TableUnchecked())[half_page_table_entry_count..][0..half_page_table_entry_count];
    @memcpy(root_page_tables[0].toHigherHalfVirtualAddress().access(paging.PML4TE)[half_page_table_entry_count..][0..half_page_table_entry_count], src_half);

    const pdp = cpu_page_table_physical_region_iterator.takeSlice(paging.page_table_size);
    const pd = cpu_page_table_physical_region_iterator.takeSlice(paging.page_table_size);
    const pt = cpu_page_table_physical_region_iterator.takeSlice(paging.page_table_size);
    assert(cpu_page_table_physical_region_iterator.size == 0);

    const pdp_table = pdp.toHigherHalfVirtualAddress().access(paging.PDPTE);
    // log.debug("pdp index: {}. pdp table: 0x{x}", .{ paging.CPUPageTables.pdp_index, @ptrToInt(pdp_table.ptr) });
    pdp_table[paging.CPUPageTables.pdp_index] = paging.PDPTE{
        .present = true,
        .write = true,
        .execute_disable = false,
        .address = paging.packAddress(paging.PDPTE, pd.address.value()),
    };

    const pd_table = pd.toHigherHalfVirtualAddress().access(paging.PDTE);
    pd_table[paging.CPUPageTables.pd_index] = paging.PDTE{
        .present = true,
        .write = true,
        .execute_disable = false,
        .address = paging.packAddress(paging.PDTE, pt.address.value()),
    };

    const supporting_page_table_size = PageTableRegions.total_size;
    _ = supporting_page_table_size;
    const indexed_base = @as(paging.IndexedVirtualAddress, @bitCast(page_table_regions.total.address.toHigherHalfVirtualAddress().value()));
    const indexed_top = @as(paging.IndexedVirtualAddress, @bitCast(page_table_regions.total.top().toHigherHalfVirtualAddress().value()));
    const diff = @as(u64, @bitCast(indexed_top)) - @as(u64, @bitCast(indexed_base));
    // log.debug("Mapping 0x{x} - 0x{x} to higher half", .{ page_table_regions.total.address.value(), page_table_regions.total.top().value() });
    // log.debug("supporting_page_table_size: {}", .{supporting_page_table_size});
    // log.debug("\nBASE: {}\n\nTOP: {}\n\n", .{ indexed_base, indexed_top });

    assert(indexed_base.PML4 == indexed_top.PML4);
    assert(indexed_base.PDP == indexed_top.PDP);
    const ptable_count = indexed_top.PD - indexed_base.PD + 1;

    const cpu_indexed_base = @as(paging.IndexedVirtualAddress, @bitCast(cpu_page_table_physical_region.toHigherHalfVirtualAddress().address.value()));
    const cpu_indexed_top = @as(paging.IndexedVirtualAddress, @bitCast(cpu_page_table_physical_region.toHigherHalfVirtualAddress().top().value()));
    const cpu_diff = @as(u64, @bitCast(cpu_indexed_top)) - @as(u64, @bitCast(cpu_indexed_base));
    // log.debug("\nCPU BASE: {}\n\nCPU TOP: {}\n\n", .{ cpu_indexed_base, cpu_indexed_top });
    assert(cpu_indexed_base.PML4 == cpu_indexed_top.PML4);
    assert(cpu_indexed_base.PDP == cpu_indexed_top.PDP);
    assert(cpu_indexed_base.PDP == indexed_base.PDP);
    assert(cpu_indexed_base.PD == cpu_indexed_top.PD);
    assert(cpu_indexed_base.PT < cpu_indexed_top.PT);
    assert(cpu_indexed_base.PML4 == indexed_base.PML4);
    assert(cpu_indexed_base.PDP == indexed_base.PDP);
    const cpu_ptable_count = cpu_indexed_top.PD - cpu_indexed_base.PD + 1;
    assert(cpu_ptable_count <= ptable_count);

    const support_pdp_table_count = 1;
    const support_pd_table_count = 1;
    const min = @min(@as(u64, @bitCast(indexed_base)), @as(u64, @bitCast(cpu_indexed_base)));
    const max = @max(@as(u64, @bitCast(indexed_top)), @as(u64, @bitCast(cpu_indexed_top)));
    const min_indexed = @as(paging.IndexedVirtualAddress, @bitCast(min));
    const general_diff = max - min;
    const pte_count = @divExact(general_diff, lib.arch.valid_page_sizes[0]);
    const support_p_table_count = 1 + pte_count / paging.page_table_entry_count + @intFromBool(@as(usize, paging.page_table_entry_count) - min_indexed.PT < pte_count);
    // log.debug("Support p table count: {}", .{support_p_table_count});
    // log.debug("indexed base: 0x{x}. top: 0x{x}", .{ @bitCast(u64, indexed_base), @bitCast(u64, indexed_top) });
    // log.debug("cpu indexed base: 0x{x}. top: 0x{x}", .{ @bitCast(u64, cpu_indexed_base), @bitCast(u64, cpu_indexed_top) });

    const support_page_table_count = @as(usize, support_pdp_table_count + support_pd_table_count + support_p_table_count);
    const support_page_table_physical_region = try cpu.driver.getRootCapability().allocatePages(support_page_table_count * paging.page_table_size);
    // log.debug("Support page tables: 0x{x} - 0x{x}", .{ support_page_table_physical_region.address.value(), support_page_table_physical_region.top().value() });
    // log.debug("PD table count: {}. P table count: {}", .{ support_pd_table_count, support_p_table_count });

    const support_pdp_offset = 0;
    const support_pd_offset = support_pdp_table_count * paging.page_table_size;
    const support_pt_offset = support_pd_offset + support_pd_table_count * paging.page_table_size;

    const support_pml4 = page_table_regions.getPageTables(.{ .user = true, .index = .pml4 });
    const support_pdp_region = support_page_table_physical_region.offset(support_pdp_offset);
    const support_pd_region = support_page_table_physical_region.offset(support_pd_offset);
    const support_pt_region = support_page_table_physical_region.offset(support_pt_offset);

    assert(!support_pml4[indexed_base.PML4].present);
    assert(support_pdp_table_count == 1);

    support_pml4[indexed_base.PML4] = paging.PML4TE{
        .present = true,
        .write = true,
        .address = paging.packAddress(paging.PML4TE, support_pdp_region.address.value()),
    };

    const support_pdp = support_pdp_region.toHigherHalfVirtualAddress().access(paging.PDPTE);
    assert(!support_pdp[indexed_base.PDP].present);
    assert(support_pd_table_count == 1);

    support_pdp[indexed_base.PDP] = paging.PDPTE{
        .present = true,
        .write = true,
        .address = paging.packAddress(paging.PDPTE, support_pd_region.address.value()),
    };

    const support_pd = support_pd_region.toHigherHalfVirtualAddress().access(paging.PDTE);
    assert(!support_pd[indexed_base.PD].present);
    assert(indexed_base.PD <= cpu_indexed_base.PD);

    for (0..support_p_table_count) |i| {
        const pd_index = indexed_base.PD + i;
        const p_table_physical_region = support_pt_region.offset(i * paging.page_table_size);
        support_pd[pd_index] = paging.PDTE{
            .present = true,
            .write = true,
            .address = paging.packAddress(paging.PDTE, p_table_physical_region.address.value()),
        };
    }

    const support_ptes = support_pt_region.toHigherHalfVirtualAddress().access(paging.PTE);
    for (0..@divExact(diff, lib.arch.valid_page_sizes[0])) |page_index| {
        support_ptes[indexed_base.PT + page_index] = paging.getPageEntry(paging.PTE, page_table_regions.total.offset(page_index * lib.arch.valid_page_sizes[0]).address.value(), .{
            .present = true,
            .write = true,
        });
    }

    for (0..@divExact(cpu_diff, lib.arch.valid_page_sizes[0])) |page_index| {
        support_ptes[cpu_indexed_base.PT + page_index] = paging.getPageEntry(paging.PTE, cpu_page_table_physical_region.offset(page_index * lib.arch.valid_page_sizes[0]).address.value(), .{
            .present = true,
            .write = true,
        });
    }

    {
        const privileged_stack_physical_region = try cpu.driver.getRootCapability().allocatePages(x86_64.capability_address_space_stack_size);
        const indexed_privileged_stack = @as(paging.IndexedVirtualAddress, @bitCast(x86_64.capability_address_space_stack_address.value()));
        const stack_last_page = x86_64.capability_address_space_stack_address.offset(x86_64.capability_address_space_stack_size - lib.arch.valid_page_sizes[0]);
        const indexed_privileged_stack_last_page = @as(paging.IndexedVirtualAddress, @bitCast(stack_last_page.value()));
        assert(indexed_privileged_stack.PD == indexed_privileged_stack_last_page.PD);
        assert(indexed_privileged_stack.PT < indexed_privileged_stack_last_page.PT);

        const pml4te = &page_table_regions.getPageTables(.{ .index = .pml4, .user = false })[indexed_privileged_stack.PML4];
        assert(pml4te.present);

        const pdpte = &(try paging.accessPageTable(PhysicalAddress.new(paging.unpackAddress(pml4te)), *paging.PDPTable))[indexed_privileged_stack.PDP];
        assert(!pdpte.present);
        const pd_table_physical_region = try cpu.driver.getRootCapability().allocatePages(paging.page_table_size);
        pdpte.* = paging.PDPTE{
            .present = true,
            .write = true,
            .address = paging.packAddress(paging.PDTE, pd_table_physical_region.address.value()),
        };

        const pdte = &(try paging.accessPageTable(PhysicalAddress.new(paging.unpackAddress(pdpte)), *paging.PDTable))[indexed_privileged_stack.PD];
        assert(!pdte.present);
        const p_table_physical_region = try cpu.driver.getRootCapability().allocatePages(paging.page_table_size);
        pdte.* = paging.PDTE{
            .present = true,
            .write = true,
            .address = paging.packAddress(paging.PDTE, p_table_physical_region.address.value()),
        };

        const p_table = try paging.accessPageTable(PhysicalAddress.new(paging.unpackAddress(pdte)), *paging.PTable);
        for (p_table[indexed_privileged_stack.PT .. @as(usize, indexed_privileged_stack_last_page.PT) + 1], 0..) |*pte, index| {
            const physical_address = privileged_stack_physical_region.offset(index * paging.page_table_size).address;
            pte.* = paging.getPageEntry(paging.PTE, physical_address.value(), .{
                .present = true,
                .write = true,
            });
        }
    }

    const init_cpu_scheduler_physical_region = try cpu.driver.getRootCapability().allocatePages(@sizeOf(cpu.UserScheduler));
    const init_cpu_scheduler_virtual_region = init_cpu_scheduler_physical_region.toHigherHalfVirtualAddress();
    const init_cpu_scheduler = init_cpu_scheduler_virtual_region.address.access(*cpu.UserScheduler);
    // log.debug("Init scheduler: 0x{x}", .{init_cpu_scheduler_virtual_region.address.value()});
    const cpu_scheduler_indexed = @as(paging.IndexedVirtualAddress, @bitCast(init_cpu_scheduler_virtual_region.address.value()));
    // log.debug("CPU scheduler indexed: {}", .{cpu_scheduler_indexed});

    assert(cpu_scheduler_indexed.PML4 == cpu_indexed_base.PML4);

    const scheduler_pml4te = &page_table_regions.getPageTables(.{ .index = .pml4, .user = true })[cpu_scheduler_indexed.PML4];
    assert(scheduler_pml4te.present);

    const scheduler_pdpte = &(try paging.accessPageTable(PhysicalAddress.new(paging.unpackAddress(scheduler_pml4te)), *paging.PDPTable))[cpu_scheduler_indexed.PDP];

    // Sanity checks

    const scheduler_pdte = blk: {
        const pdp_is_inside = cpu_scheduler_indexed.PDP >= cpu_indexed_base.PDP and cpu_scheduler_indexed.PDP <= cpu_indexed_top.PDP;
        // log.debug("PDP inside: {}", .{pdp_is_inside});
        assert(scheduler_pdpte.present == pdp_is_inside);

        if (!scheduler_pdpte.present) {
            const pdte_allocation = try cpu.driver.getRootCapability().allocatePages(paging.page_table_size);
            scheduler_pdpte.* = .{
                .present = true,
                .write = true,
                .address = paging.packAddress(@TypeOf(scheduler_pdpte.*), pdte_allocation.address.value()),
            };
        }

        break :blk &(try paging.accessPageTable(PhysicalAddress.new(paging.unpackAddress(scheduler_pdpte)), *paging.PDTable))[cpu_scheduler_indexed.PD];
    };

    const scheduler_pte = blk: {
        const is_inside_cpu_page_table_limits = cpu_scheduler_indexed.PD >= cpu_indexed_base.PD and cpu_scheduler_indexed.PD <= cpu_indexed_top.PD;
        assert(is_inside_cpu_page_table_limits == scheduler_pdte.present);
        if (!scheduler_pdte.present) {
            const pte_allocation = try cpu.driver.getRootCapability().allocatePages(paging.page_table_size);
            scheduler_pdte.* = .{
                .present = true,
                .write = true,
                .address = paging.packAddress(@TypeOf(scheduler_pdte.*), pte_allocation.address.value()),
            };
        }

        break :blk &(try paging.accessPageTable(PhysicalAddress.new(paging.unpackAddress(scheduler_pdte)), *paging.PTable))[cpu_scheduler_indexed.PT];
    };

    scheduler_pte.* = paging.getPageEntry(paging.PTE, init_cpu_scheduler_physical_region.address.value(), .{
        .present = true,
        .write = true,
    });

    init_cpu_scheduler.* = cpu.UserScheduler{
        .common = user_scheduler_virtual_address.access(*rise.UserScheduler),
        .capability_root_node = cpu.capabilities.Root{
            .static = .{
                .cpu = true,
                .boot = true,
                .process = true,
            },
            .dynamic = .{
                .io = .{
                    .debug = true,
                },
                .ram = cpu.driver.getRootCapability().dynamic.ram,
                .cpu_memory = .{
                    .flags = .{
                        .allocate = true,
                    },
                },
                .page_table = .{},
            },
            .scheduler = .{
                .handle = init_cpu_scheduler,
                .memory = scheduler_memory_physical_region,
            },
        },
    };

    const higher_half_scheduler_common = scheduler_memory_physical_region.address.toHigherHalfVirtualAddress().access(*rise.UserScheduler);
    // log.debug("Higher half: 0x{x}", .{@ptrToInt(higher_half_scheduler_common)});
    higher_half_scheduler_common.disabled = true;
    higher_half_scheduler_common.core_id = cpu.core_id;

    // log.debug("cpu scheduler: 0x{x}", .{@ptrToInt(init_cpu_scheduler)});

    return SpawnInitCommonResult{
        .page_table_regions = page_table_regions,
        .scheduler = init_cpu_scheduler,
    };
}
