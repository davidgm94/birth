const GDT = @This();

const std = @import("../../../common/std.zig");

const DescriptorTable = @import("descriptor_table.zig");
const TLS = @import("tls.zig");
const TSS = @import("tss.zig");
const log = std.log.scoped(.GDT);

pub const Table = packed struct {
    null_entry: Entry = 0, // 0x00
    code_16: Entry = 0x00009a000000ffff, // 0x08
    data_16: Entry = 0x000093000000ffff, // 0x10
    code_32: Entry = 0x00cf9a000000ffff, // 0x18
    data_32: Entry = 0x00cf93000000ffff, // 0x20
    code_64: Entry = 0x00af9b000000ffff, // 0x28
    data_64: Entry = 0x00af93000000ffff, // 0x30
    user_code_32: Entry = 0x00cffa000000ffff, // 0x38
    user_data: Entry = 0x00cff2000000ffff, // 0x40
    user_code_64: Entry = 0x00affb000000ffff, // 0x48
    // We don't need a user data 64 selector because 32 bit is enough, most values are not relevant
    tss: TSS.Descriptor,

    comptime {
        const entry_count = 10;
        std.assert(@sizeOf(Table) == entry_count * @sizeOf(Entry) + @sizeOf(TSS.Descriptor));
        std.assert(@offsetOf(Table, "code_64") == 0x28);
        std.assert(@offsetOf(Table, "data_64") == 0x30);
        std.assert(@offsetOf(Table, "user_code_32") == 0x38);
        std.assert(@offsetOf(Table, "user_data") == 0x40);
        std.assert(@offsetOf(Table, "user_code_64") == 0x48);
        std.assert(@offsetOf(Table, "tss") == entry_count * @sizeOf(Entry));
    }

    pub fn initial_setup(gdt: *Table, cpu_id: u64) void {
        log.debug("Loading GDT...", .{});
        gdt.* = Table{
            .tss = bootstrap_tss.get_descriptor(),
        };
        gdt.load();

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
        TLS.preset(cpu_id);
        log.debug("GDT loaded", .{});
    }

    pub inline fn load(gdt: *Table) void {
        const register = DescriptorTable.Register{
            .limit = @sizeOf(Table) - 1,
            .address = @ptrToInt(gdt),
        };

        asm volatile (
            \\  lgdt %[gdt_register]
            :
            : [gdt_register] "*p" (&register),
        );
    }

    pub inline fn update_tss(gdt: *Table, tss: *TSS.Struct) void {
        gdt.tss = tss.get_descriptor();
        const tss_selector: u16 = @offsetOf(Table, "tss");
        asm volatile (
            \\ltr %[tss_selector]
            :
            : [tss_selector] "r" (tss_selector),
        );
        log.debug("Updated TSS", .{});
    }
};

const bootstrap_tss = TSS.Struct{};

const Entry = u64;

pub fn save() DescriptorTable.Register {
    var register: DescriptorTable.Register = undefined;
    asm volatile ("sgdt %[gdt_register]"
        :
        : [gdt_register] "*p" (&register),
    );

    return register;
}
