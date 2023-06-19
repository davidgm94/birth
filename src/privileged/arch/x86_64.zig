const x86 = @import("x86/common.zig");
pub usingnamespace x86;

const lib = @import("lib");
const assert = lib.assert;
const cpuid = lib.arch.x86_64.CPUID;

const privileged = @import("privileged");

pub const APIC = @import("x86/64/apic.zig");
pub const io = @import("x86/64/io.zig");
pub const paging = @import("x86/64/paging.zig");
pub const registers = @import("x86/64/registers.zig");

pub const valid_page_sizes = privileged.arch.valid_page_sizes;
pub const page_size = valid_page_sizes[0];
pub const reasonable_page_size = valid_page_sizes[1];

pub fn page_shifter(comptime asked_page_size: comptime_int) comptime_int {
    return @ctz(@as(u32, asked_page_size));
}

/// Returns the maximum number bits a physical address is allowed to have in this CPU
pub inline fn get_max_physical_address_bit() u6 {
    return @as(u6, @truncate(cpuid(0x80000008).eax));
}

pub const GDT = extern struct {
    pub const Entry = packed struct(u64) {
        limit_low: u16,
        base_low: u16,
        base_mid: u8,
        access: packed struct(u8) {
            accessed: bool,
            read_write: bool,
            direction_conforming: bool,
            executable: bool,
            code_data_segment: bool,
            dpl: u2,
            present: bool,
        },
        limit_high: u4,
        reserved: u1 = 0,
        long_mode: bool,
        size_flag: bool,
        granularity: bool,
        base_high: u8 = 0,

        pub const null_entry = Entry{
            .limit_low = 0,
            .base_low = 0,
            .base_mid = 0,
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
        };

        pub const code_16 = Entry{
            .limit_low = 0xffff,
            .base_low = 0,
            .base_mid = 0,
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
        };

        pub const data_16 = Entry{
            .limit_low = 0xffff,
            .base_low = 0,
            .base_mid = 0,
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
        };

        pub const code_32 = Entry{
            .limit_low = 0xffff,
            .base_low = 0,
            .base_mid = 0,
            .access = .{
                .accessed = false,
                .read_write = true,
                .direction_conforming = false,
                .executable = true,
                .code_data_segment = true,
                .dpl = 0,
                .present = true,
            },
            .limit_high = 0xf,
            .long_mode = false,
            .size_flag = true,
            .granularity = true,
        };

        pub const data_32 = Entry{
            .limit_low = 0xffff,
            .base_low = 0,
            .base_mid = 0,
            .access = .{
                .accessed = false,
                .read_write = true,
                .direction_conforming = false,
                .executable = false,
                .code_data_segment = true,
                .dpl = 0,
                .present = true,
            },
            .limit_high = 0xf,
            .long_mode = false,
            .size_flag = true,
            .granularity = true,
        };

        pub const code_64 = Entry{
            .limit_low = 0xffff,
            .base_low = 0,
            .base_mid = 0,
            .access = .{
                .accessed = false,
                .read_write = true,
                .direction_conforming = false,
                .executable = true,
                .code_data_segment = true,
                .dpl = 0,
                .present = true,
            },
            .limit_high = 0xf,
            .long_mode = true,
            .size_flag = false,
            .granularity = false,
        };

        pub const data_64 = Entry{
            .limit_low = 0xffff,
            .base_low = 0,
            .base_mid = 0,
            .access = .{
                .accessed = false,
                .read_write = true,
                .direction_conforming = false,
                .executable = false,
                .code_data_segment = true,
                .dpl = 0,
                .present = true,
            },
            .limit_high = 0xf,
            .long_mode = false,
            .size_flag = false,
            .granularity = false,
        };

        pub const user_data_64 = Entry{
            .limit_low = 0xffff,
            .base_low = 0,
            .base_mid = 0,
            .access = .{
                .accessed = false,
                .read_write = true,
                .direction_conforming = false,
                .executable = false,
                .code_data_segment = true,
                .dpl = 3,
                .present = true,
            },
            .limit_high = 0xf,
            .long_mode = false,
            .size_flag = false,
            .granularity = true,
        };

        pub const user_code_64 = Entry{
            .limit_low = 0xffff,
            .base_low = 0,
            .base_mid = 0,
            .access = .{
                .accessed = false,
                .read_write = true,
                .direction_conforming = false,
                .executable = true,
                .code_data_segment = true,
                .dpl = 3,
                .present = true,
            },
            .limit_high = 0xf,
            .long_mode = true,
            .size_flag = false,
            .granularity = true,
        };
    };

    pub const Descriptor = x86.SegmentDescriptor;
};

pub const TicksPerMS = extern struct {
    tsc: u32,
    lapic: u32,
};
