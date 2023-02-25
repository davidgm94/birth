const GDT = @This();

const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.GDT);

const privileged = @import("privileged");
const DescriptorTable = privileged.arch.x86_64.DescriptorTable;
const TSS = privileged.arch.x86_64.TSS;

pub const Descriptor = DescriptorTable.Register;

pub const Entry = packed struct(u64) {
    limit_low: u16 = lib.maxInt(u16),
    base_low: u16 = 0,
    base_mid: u8 = 0,
    access: packed struct(u8) {
        accessed: bool,
        read_write: bool,
        direction_conforming: bool,
        executable: bool,
        code_data_segment: bool,
        dpl: u2,
        present: bool,
    },
    limit_high: u4 = lib.maxInt(u4),
    reserved: u1 = 0,
    long_mode: bool,
    size_flag: bool,
    granularity: bool,
    base_high: u8 = 0,
};

// This is the most basic x86_64 GDT
pub const Table = extern struct {
    // 0x00
    null_entry: Entry = .{
        .limit_low = 0,
        .access = .{
            .accessed = false,
            .read_write = false,
            .direction_conforming = false,
            .executable = false,
            .code_data_segment = false,
            .dpl = 0,
            .present = false,
        },
        .limit_high = 0,
        .long_mode = false,
        .size_flag = false,
        .granularity = false,
    },
    // 0x08
    code_16: Entry = .{
        .limit_low = 0,
        .access = .{
            .accessed = false,
            .read_write = true,
            .direction_conforming = false,
            .executable = true,
            .code_data_segment = true,
            .dpl = 0,
            .present = true,
        },
        .limit_high = 0,
        .long_mode = false,
        .size_flag = false,
        .granularity = false,
    },
    // 0x10
    data_16: Entry = .{
        .limit_low = 0,
        .access = .{
            .accessed = false,
            .read_write = true,
            .direction_conforming = false,
            .executable = false,
            .code_data_segment = true,
            .dpl = 0,
            .present = true,
        },
        .limit_high = 0,
        .long_mode = false,
        .size_flag = false,
        .granularity = false,
    },
    // 0x18
    code_32: Entry = .{
        .access = .{
            .accessed = false,
            .read_write = true,
            .direction_conforming = false,
            .executable = true,
            .code_data_segment = true,
            .dpl = 0,
            .present = true,
        },
        .long_mode = false,
        .size_flag = true,
        .granularity = true,
    },
    // 0x20
    data_32: Entry = .{
        .access = .{
            .accessed = false,
            .read_write = true,
            .direction_conforming = false,
            .executable = false,
            .code_data_segment = true,
            .dpl = 0,
            .present = true,
        },
        .long_mode = false,
        .size_flag = true,
        .granularity = true,
    },
    // 0x28
    code_64: Entry = .{
        .access = .{
            .accessed = false,
            .read_write = true,
            .direction_conforming = false,
            .executable = true,
            .code_data_segment = true,
            .dpl = 0,
            .present = true,
        },
        .long_mode = true,
        .size_flag = true,
        .granularity = true,
    },
    // 0x30
    data_64: Entry = .{
        .access = .{
            .accessed = false,
            .read_write = true,
            .direction_conforming = false,
            .executable = false,
            .code_data_segment = true,
            .dpl = 0,
            .present = true,
        },
        .long_mode = false,
        .size_flag = true,
        .granularity = true,
    },
    // 0x38
    user_data_64: Entry = .{
        .access = .{
            .accessed = false,
            .read_write = true,
            .direction_conforming = false,
            .executable = false,
            .code_data_segment = true,
            .dpl = 3,
            .present = true,
        },
        .long_mode = false,
        .size_flag = true,
        .granularity = true,
    },
    // 0x40
    user_code_64: Entry = .{
        .access = .{
            .accessed = false,
            .read_write = true,
            .direction_conforming = false,
            .executable = true,
            .code_data_segment = true,
            .dpl = 3,
            .present = true,
        },
        .long_mode = true,
        .size_flag = true,
        .granularity = true,
    },
    // We don't need a user data 64 selector because 32 bit is enough, most values are not relevant
    tss_descriptor: TSS.Descriptor = undefined,
    tss: TSS.Struct align(8) = .{},

    comptime {
        const entry_count = 9;
        const target_size = entry_count * @sizeOf(Entry) + @sizeOf(TSS.Descriptor) + @sizeOf(TSS.Struct);

        assert(@sizeOf(Table) == target_size);
        assert(@offsetOf(Table, "code_64") == 0x28);
        assert(@offsetOf(Table, "data_64") == 0x30);
        assert(@offsetOf(Table, "user_data_64") == 0x38);
        assert(@offsetOf(Table, "user_code_64") == 0x40);
        assert(@offsetOf(Table, "tss_descriptor") == entry_count * @sizeOf(Entry));
    }

    pub fn setup(gdt: *Table, offset: u64, comptime flush_segment_registers: bool) void {
        const descriptor = gdt.fill_with_kernel_memory_offset(offset);
        load(descriptor);

        if (flush_segment_registers) {
            // Flush segments
            asm volatile (
                \\xor %%rax, %%rax
                \\mov %[data_segment_selector], %%rax
                \\mov %%rax, %%ds
                \\mov %%rax, %%es
                \\mov %%rax, %%fs
                \\mov %%rax, %%gs
                :
                : [data_segment_selector] "i" (@as(u64, @offsetOf(GDT.Table, "data_64"))),
            );
        }
    }

    pub fn getDescriptor(gdt: *const GDT.Table) GDT.Descriptor {
        return .{
            .limit = @offsetOf(GDT.Table, "tss"),
            .address = @ptrToInt(gdt),
        };
    }

    pub inline fn load(descriptor: DescriptorTable.Register) void {
        asm volatile (
            \\  lgdt %[gdt_register]
            :
            : [gdt_register] "*p" (&descriptor),
        );
    }

    pub inline fn update_tss(gdt: *Table, tss: *TSS.Struct) void {
        gdt.tss = tss.get_descriptor();
        const tss_selector: u16 = @offsetOf(Table, "tss_descriptor");
        asm volatile (
            \\ltr %[tss_selector]
            :
            : [tss_selector] "r" (tss_selector),
        );
        log.debug("Updated TSS", .{});
    }
};

pub fn save() DescriptorTable.Register {
    var register: DescriptorTable.Register = undefined;
    asm volatile ("sgdt %[gdt_register]"
        :
        : [gdt_register] "*p" (&register),
    );

    return register;
}
