const std = @import("std.zig");

pub fn Bitflag(comptime is_volatile: bool, comptime BackingType: type, comptime EnumT: type) type {
    return struct {
        pub const Enum = EnumT;
        pub const Int = BackingType;
        const EnumBitSize = @popCount(u64, @bitSizeOf(BackingType) - 1);
        comptime {
            std.assert(EnumBitSize == @bitSizeOf(EnumT));
        }
        const Ptr = if (is_volatile) *volatile @This() else *@This();

        bits: Int,

        pub inline fn from_flags(comptime flags: []const EnumT) @This() {
            const result = comptime blk: {
                if (flags.len > @bitSizeOf(EnumT)) @compileError("More flags than bits\n");

                comptime var bits: Int = 0;

                inline for (flags) |field| {
                    bits |= 1 << @enumToInt(field);
                }

                break :blk bits;
            };
            return @This(){ .bits = result };
        }

        pub fn from_bits(bits: Int) @This() {
            return @This(){ .bits = bits };
        }

        pub inline fn from_flag(comptime flag: EnumT) @This() {
            const bits = 1 << @enumToInt(flag);
            return @This(){ .bits = bits };
        }

        pub inline fn empty() @This() {
            return @This(){
                .bits = 0,
            };
        }

        pub inline fn all() @This() {
            var result = comptime blk: {
                var bits: Int = 0;
                inline for (@typeInfo(EnumT).Enum.fields) |field| {
                    bits |= 1 << field.value;
                }
                break :blk @This(){
                    .bits = bits,
                };
            };
            return result;
        }

        pub inline fn is_empty(self: @This()) bool {
            return self.bits == 0;
        }

        /// This assumes invalid values in the flags can't be set.
        pub inline fn is_all(self: @This()) bool {
            return all().bits == self.bits;
        }

        pub inline fn contains(self: @This(), comptime flag: EnumT) bool {
            return ((self.bits & (1 << @enumToInt(flag))) >> @enumToInt(flag)) != 0;
        }

        // TODO: create a mutable version of this
        pub inline fn or_flag(self: Ptr, comptime flag: EnumT) void {
            self.bits |= 1 << @enumToInt(flag);
        }

        pub fn format(bitflag: @This(), comptime _: []const u8, _: std.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
            try writer.writeAll("{\n");
            for (std.enum_values(Enum)) |enum_value| {
                const bit_value = @boolToInt(bitflag.bits & (@as(Int, 1) << @intCast(u6, @enumToInt(enum_value))) != 0);
                try std.internal_format(writer, "\t{s}: {}\n", .{ @tagName(enum_value), bit_value });
            }
            try writer.writeAll("}");
        }
    };
}
