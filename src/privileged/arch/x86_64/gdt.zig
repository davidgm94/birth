const GDT = @This();

const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.GDT);

const privileged = @import("privileged");
const DescriptorTable = privileged.arch.x86_64.DescriptorTable;
const TSS = privileged.arch.x86_64.TSS;

pub const Descriptor = DescriptorTable.Register;

// This is the most basic x86_64 GDT
pub const Table = extern struct {
    null_entry: Entry = 0, // 0x00
    code_64: Entry = 0x00af9b000000ffff, // 0x08
    data_64: Entry = 0x00af93000000ffff, // 0x10
    user_data_64: Entry = 0x00cff2000000ffff, // 0x18
    user_code_64: Entry = 0x00affb000000ffff, // 0x20
    // We don't need a user data 64 selector because 32 bit is enough, most values are not relevant
    tss_descriptor: TSS.Descriptor,
    tss: TSS.Struct align(8) = .{},

    comptime {
        const entry_count = 5;
        const target_size = entry_count * @sizeOf(Entry) + @sizeOf(TSS.Descriptor) + @sizeOf(TSS.Struct);

        assert(@sizeOf(Table) == target_size);
        assert(@offsetOf(Table, "code_64") == 0x08);
        assert(@offsetOf(Table, "data_64") == 0x10);
        assert(@offsetOf(Table, "user_data_64") == 0x18);
        assert(@offsetOf(Table, "user_code_64") == 0x20);
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

    pub fn fill_with_kernel_memory_offset(gdt: *Table, offset: u64) DescriptorTable.Register {
        gdt.* = Table{
            .tss_descriptor = undefined, // Leave it undefined until later
        };

        return DescriptorTable.Register{
            .limit = get_size() - 1,
            .address = @ptrToInt(gdt) + offset,
        };
    }

    pub fn get_size() u16 {
        return @offsetOf(GDT.Table, "tss");
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

const Entry = u64;

pub fn save() DescriptorTable.Register {
    var register: DescriptorTable.Register = undefined;
    asm volatile ("sgdt %[gdt_register]"
        :
        : [gdt_register] "*p" (&register),
    );

    return register;
}
