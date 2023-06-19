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
const cr0 = x86_64.registers.cr0;
const cr3 = x86_64.registers.cr3;
const cr4 = x86_64.registers.cr4;
const PhysicalAddress = lib.PhysicalAddress;
const PhysicalMemoryRegion = lib.PhysicalMemoryRegion;
const VirtualAddress = lib.VirtualAddress;
const VirtualMemoryRegion = lib.VirtualMemoryRegion;

const cpu = @import("cpu");
const Heap = cpu.Heap;

const init = @import("./x86/64/init.zig");
pub const syscall = @import("./x86/64/syscall.zig");
pub const entryPoint = init.entryPoint;

const rise = @import("rise");

var writer_lock: Spinlock = .released;

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

const interrupt_kind: u32 = 0;

export fn interruptHandler(regs: *const InterruptRegisters, interrupt_number: u8) void {
    switch (interrupt_number) {
        local_timer_vector => {
            APIC.write(.eoi, 0);
            nextTimer(10);
        },
        else => cpu.panicFromInstructionPointerAndFramePointer(regs.rip, regs.rbp, "Exception: 0x{x}", .{interrupt_number}),
    }
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

const local_timer_vector = 0xef;
pub export var ticks_per_ms: privileged.arch.x86_64.TicksPerMS = undefined;
pub inline fn nextTimer(ms: u32) void {
    APIC.write(.lvt_timer, local_timer_vector | (1 << 17));
    APIC.write(.timer_initcnt, ticks_per_ms.lapic * ms);
}
pub const kpti = true;
pub const pcid = false;
pub const smap = false;
pub const invariant_tsc = false;
pub const capability_address_space_size = 1 * lib.gb;
pub const capability_address_space_start = capability_address_space_stack_top - capability_address_space_size;
pub const capability_address_space_stack_top = 0xffff_ffff_8000_0000;
pub const capability_address_space_stack_size = privileged.default_stack_size;
pub const capability_address_space_stack_alignment = lib.arch.valid_page_sizes[0];
pub const capability_address_space_stack_address = VirtualAddress.new(capability_address_space_stack_top - capability_address_space_stack_size);
pub const code_64 = @offsetOf(GDT, "code_64");
pub const data_64 = @offsetOf(GDT, "data_64");
pub const user_code_64 = @offsetOf(GDT, "user_code_64");
pub const user_data_64 = @offsetOf(GDT, "user_data_64");
pub const tss_selector = @offsetOf(GDT, "tss_descriptor");
pub const user_code_selector = user_code_64 | user_dpl;
pub const user_data_selector = user_data_64 | user_dpl;
pub const user_dpl = 3;

pub const GDT = extern struct {
    null: Entry = GDT.Entry.null_entry, // 0x00
    code_16: Entry = GDT.Entry.code_16, // 0x08
    data_16: Entry = GDT.Entry.data_16, // 0x10
    code_32: Entry = GDT.Entry.code_32, // 0x18
    data_32: Entry = GDT.Entry.data_32, // 0x20
    code_64: u64 = 0x00A09A0000000000, // 0x28
    data_64: u64 = 0x0000920000000000, // 0x30
    user_data_64: u64 = @as(u64, 0x0000920000000000) | (3 << 45), //GDT.Entry.user_data_64, // 0x38
    user_code_64: u64 = @as(u64, 0x00A09A0000000000) | (3 << 45), //GDT.Entry.user_code_64, // 0x40
    tss_descriptor: TSS.Descriptor = undefined, // 0x48

    const Entry = privileged.arch.x86_64.GDT.Entry;

    pub const Descriptor = privileged.arch.x86_64.GDT.Descriptor;

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
            .address = @intFromPtr(global_descriptor_table),
        };
    }
};

pub const SystemSegmentDescriptor = extern struct {
    const Type = enum(u4) {
        ldt = 0b0010,
        tss_available = 0b1001,
        tss_busy = 0b1011,
        call_gate = 0b1100,
        interrupt_gate = 0b1110,
        trap_gate = 0b1111,
    };
};

pub const TSS = extern struct {
    reserved0: u32 = 0,
    rsp: [3]u64 align(4) = [3]u64{ 0, 0, 0 },
    reserved1: u64 align(4) = 0,
    IST: [7]u64 align(4) = [7]u64{ 0, 0, 0, 0, 0, 0, 0 },
    reserved3: u64 align(4) = 0,
    reserved4: u16 = 0,
    IO_map_base_address: u16 = 104,

    comptime {
        assert(@sizeOf(TSS) == 104);
    }

    pub const Descriptor = extern struct {
        limit_low: u16,
        base_low: u16,
        base_mid_low: u8,
        access: Access,
        attributes: Attributes,
        base_mid_high: u8,
        base_high: u32,
        reserved: u32 = 0,

        pub const Access = packed struct(u8) {
            type: SystemSegmentDescriptor.Type,
            reserved: u1 = 0,
            dpl: u2,
            present: bool,
        };

        pub const Attributes = packed struct(u8) {
            limit: u4,
            available_for_system_software: bool,
            reserved: u2 = 0,
            granularity: bool,
        };

        comptime {
            assert(@sizeOf(TSS.Descriptor) == 0x10);
        }
    };

    pub fn getDescriptor(tss_struct: *const TSS, offset: u64) Descriptor {
        const address = @intFromPtr(tss_struct) + offset;
        return Descriptor{
            .low = .{
                .limit_low = @as(u16, @truncate(@sizeOf(TSS) - 1)),
                .base_low = @as(u16, @truncate(address)),
                .base_low_mid = @as(u8, @truncate(address >> 16)),
                .type = 0b1001,
                .descriptor_privilege_level = 0,
                .present = 1,
                .limit_high = 0,
                .available_for_system_software = 0,
                .granularity = 0,
                .base_mid = @as(u8, @truncate(address >> 24)),
            },
            .base_high = @as(u32, @truncate(address >> 32)),
        };
    }
};

pub const IDT = extern struct {
    descriptors: [entry_count]GateDescriptor = undefined,
    pub const Descriptor = privileged.arch.x86_64.SegmentDescriptor;
    pub const GateDescriptor = extern struct {
        offset_low: u16,
        segment_selector: u16,
        flags: packed struct(u16) {
            ist: u3,
            reserved: u5 = 0,
            type: SystemSegmentDescriptor.Type,
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

pub inline fn writerStart() void {
    writer_lock.acquire();
}

pub inline fn writerEnd() void {
    writer_lock.release();
}

pub const PageTableEntry = paging.Level;
pub const root_page_table_entry = @as(cpu.arch.PageTableEntry, @enumFromInt(0));

pub const IOMap = extern struct {
    debug: bool,
};
