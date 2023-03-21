const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.Syscall);

pub const Convention = enum(u1) {
    linux = 0,
    rise = 1,
};

const NumberInteger = lib.IntType(.unsigned, @bitSizeOf(u64) - @bitSizeOf(Convention));

pub const Rise = enum(NumberInteger) {
    qemu_exit = 50,
    print = 51,
};

pub const Linux = enum(NumberInteger) {
    read = 0,
    write = 1,
};

pub const Number = packed struct(u64) {
    number: NumberInteger,
    convention: Convention,
};

pub const Arguments = extern struct {
    number: Number,
    arguments: [6]u64,

    comptime {
        assert(@sizeOf(Arguments) == 7 * @sizeOf(u64));
    }
};
