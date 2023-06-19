const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.Syscall);

const rise = @import("rise");
const capabilities = rise.capabilities;

pub const argument_count = 6;
pub const Arguments = [argument_count]usize;

pub const Convention = enum(u1) {
    linux = 0,
    rise = 1,
};

pub const Options = extern union {
    general: General,
    rise: Rise,
    linux: Linux,

    pub const General = packed struct(u64) {
        number: Number,
        convention: Convention,

        pub const Number = lib.IntType(.unsigned, union_space_bits);

        comptime {
            assertSize(@This());
        }

        pub inline fn getNumberInteger(general: General, comptime convention: Convention) NumberIntegerType(convention) {
            const options_integer = @as(u64, @bitCast(general));
            return @as(NumberIntegerType(convention), @truncate(options_integer));
        }

        pub fn NumberIntegerType(comptime convention: Convention) type {
            return switch (convention) {
                .rise => Rise.IDInteger,
                .linux => u64,
            };
        }
    };

    pub const Rise = packed struct(u64) {
        type: capabilities.Type,
        command: capabilities.Subtype,
        reserved: lib.IntType(.unsigned, @bitSizeOf(u64) - @bitSizeOf(capabilities.Type) - @bitSizeOf(capabilities.Subtype) - @bitSizeOf(Convention)) = 0,
        convention: Convention = .rise,

        comptime {
            Options.assertSize(@This());
        }

        const IDInteger = u16;
        pub const ID = enum(IDInteger) {
            qemu_exit = 0,
            print = 1,
        };
    };

    pub const Linux = enum(u64) {
        _,
        comptime {
            Options.assertSize(@This());
        }
    };

    pub const union_space_bits = @bitSizeOf(u64) - @bitSizeOf(Convention);

    fn assertSize(comptime T: type) void {
        assert(@sizeOf(T) == @sizeOf(u64));
        assert(@bitSizeOf(T) == @bitSizeOf(u64));
    }

    comptime {
        assertSize(@This());
    }
};

pub const Result = extern union {
    general: General,
    rise: Rise,
    linux: Linux,

    pub const General = extern struct {
        first: packed struct(u64) {
            argument: u63,
            convention: Convention,
        },
        second: u64,
    };

    pub const Rise = extern struct {
        first: First,
        second: Second,

        pub const First = packed struct(u64) {
            padding1: u32 = 0,
            @"error": u16 = 0,
            padding2: u8 = 0,
            padding3: u7 = 0,
            convention: Convention = .rise,
        };

        pub const Second = u64;
    };

    pub const Linux = extern struct {
        result: u64,
        reserved: u64 = 0,
    };

    fn assertSize(comptime T: type) void {
        assert(@sizeOf(T) == @sizeOf(u64));
        assert(@bitSizeOf(T) == @bitSizeOf(u64));
    }
};
