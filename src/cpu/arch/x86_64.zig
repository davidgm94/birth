const lib = @import("lib");
const assert = lib.assert;
const log = lib.log;
const bootloader = @import("bootloader");
const privileged = @import("privileged");
const x86_64 = privileged.arch.x86_64;
const TSS = x86_64.TSS;

const code_64 = @offsetOf(GDT, "code_64");
const data_64 = @offsetOf(GDT, "data_64");
const tss_selector = @offsetOf(GDT, "tss_descriptor");

const cpu = @import("cpu");

pub fn earlyInitialize(bootloader_information: *bootloader.Information) void {
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
    _ = bootloader_information;
    asm volatile (
        \\ltr %[tss_selector]
        :
        : [tss_selector] "r" (@as(u16, tss_selector)),
        : "memory"
    );

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
}

export var interrupt_stack: [0x1000]u8 align(0x1000) = undefined;

export var gdt = GDT{
    .null = GDT.Entry.null_entry,
    // 0x08
    .code_16 = GDT.Entry.code_16,
    // 0x10
    .data_16 = GDT.Entry.data_16,
    // 0x18
    .code_32 = GDT.Entry.code_32,
    // 0x20
    .data_32 = GDT.Entry.data_32,
    // 0x28
    .code_64 = GDT.Entry.code_64,
    // 0x30
    .data_64 = GDT.Entry.data_64,
    // 0x38
    .user_data_64 = GDT.Entry.user_data_64,
    // 0x40
    .user_code_64 = GDT.Entry.user_code_64,
    .tss_descriptor = undefined,
};

export var tss = TSS{};
export var idt = IDT{};

pub const GDT = extern struct {
    null: Entry, // 0x00
    code_16: Entry, // 0x08
    data_16: Entry, // 0x10
    code_32: Entry, // 0x18
    data_32: Entry, // 0x20
    code_64: Entry, // 0x28
    data_64: Entry, // 0x30
    user_data_64: Entry, // 0x38
    user_code_64: Entry, // 0x40
    tss_descriptor: TSS.Descriptor = undefined,

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
