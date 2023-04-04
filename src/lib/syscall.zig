const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.Syscall);
const Capabilities = lib.Capabilities;

pub const Convention = enum(u1) {
    linux = 0,
    rise = 1,
};

pub const Arguments = [6]u64;

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
            const options_integer = @bitCast(u64, general);
            return @truncate(NumberIntegerType(convention), options_integer);
        }

        pub fn NumberIntegerType(comptime convention: Convention) type {
            return switch (convention) {
                .rise => Rise.IDInteger,
                .linux => u64,
            };
        }
    };

    pub const Rise = packed struct(u64) {
        address: u16,
        slot: u16,
        invocation: u16,
        reserved: u8 = 0,
        flags: u7 = 0,
        convention: Convention,

        comptime {
            Options.assertSize(@This());
            assert(@bitOffsetOf(Rise, "address") == 0);
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
            padding1: u32,
            @"error": u16,
            padding2: u8,
            padding3: u7,
            convention: Convention,
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
