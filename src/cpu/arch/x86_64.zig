const lib = @import("lib");
const assert = lib.assert;
const bootloader = @import("bootloader");
const privileged = @import("privileged");
const x86_64 = privileged.arch.x86_64;
const TSS = x86_64.TSS;

pub fn earlyInitialize(bootloader_information: *bootloader.Information) void {
    _ = bootloader_information;
    @panic("TODO earlyInitialize");
}

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

    pub fn reset(global_descriptor_table: *GDT, tss: *TSS, tss_stack: []const u8) void {
        const tss_address = @ptrToInt(tss);
        global_descriptor_table.tss_descriptor = .{
            .low = .{
                .limit_low = @truncate(u16, @sizeOf(TSS) - 1),
                .base_low = @truncate(u16, tss_address),
                .base_low_mid = @truncate(u8, tss_address >> 16),
                .type = 0b1001,
                .descriptor_privilege_level = 0,
                .present = 1,
                .limit_high = 0,
                .available_for_system_software = 0,
                .granularity = 0,
                .base_mid = @truncate(u8, tss_address >> 24),
            },
            .base_high = @truncate(u32, tss_address >> 32),
        };
        _ = tss_stack;

        @panic("TODO gdtReset");
    }

    pub fn getDescriptor(global_descriptor_table: *const GDT) GDT.Descriptor {
        return .{
            .limit = @sizeOf(GDT) - 1,
            .address = @ptrToInt(global_descriptor_table),
        };
    }

    pub inline fn updateTSS(global_descriptor_table: *GDT, tss: *TSS.Struct) void {
        global_descriptor_table.tss = tss.get_descriptor();
        const tss_selector: u16 = @offsetOf(GDT, "tss_descriptor");
        asm volatile (
            \\ltr %[tss_selector]
            :
            : [tss_selector] "r" (tss_selector),
        );
    }
};
