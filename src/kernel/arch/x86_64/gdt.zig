const kernel = @import("../../kernel.zig");
const DescriptorTable = @import("descriptor_table.zig");
const TSS = @import("tss.zig");

pub const Table = packed struct {
    null_entry: Entry = 0, // 0x00
    code_16: Entry = 0x00009a000000ffff, // 0x08
    data_16: Entry = 0x000093000000ffff, // 0x10
    code_32: Entry = 0x00cf9a000000ffff, // 0x18
    data_32: Entry = 0x00cf93000000ffff, // 0x20
    code_64: Entry = 0x00af9b000000ffff, // 0x28
    data_64: Entry = 0x00af93000000ffff, // 0x30
    user_code_64: Entry = 0x00affb000000ffff, // 0x38
    user_data_64: Entry = 0x00aff3000000ffff, // 0x40
    tss: TSS.Descriptor, // 0x48

    comptime {
        kernel.assert_unsafe(@sizeOf(Table) == 9 * @sizeOf(Entry) + @sizeOf(TSS.Descriptor));
        kernel.assert_unsafe(@offsetOf(Table, "tss") == 9 * @sizeOf(Entry));
    }

    pub fn initial_setup(gdt: *Table) void {
        gdt.tss = tss.get_descriptor();
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
};

var tss: TSS.Struct = undefined;

const Entry = u64;

pub fn save() DescriptorTable.Register {
    var register: DescriptorTable.Register = undefined;
    asm volatile ("sgdt %[gdt_register]"
        :
        : [gdt_register] "*p" (&register),
    );

    return register;
}
