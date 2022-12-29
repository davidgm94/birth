pub const Error = error{
    name_too_long,
    bad_value,
};

pub const max_charset_size = 6;

pub const Table = struct {
    character_set: []const u8,
    unicode_to_character: *const fn (wchar: u16, char_string: []u8) Error!void,
    character_to_unicode: *const fn (char_string: []u8) Error!u16,
    character_set_to_lower: []const u8,
    character_set_to_upper: []const u8,

    pub fn to_upper(table: *const Table, char: u8) u8 {
        const possible_result = table.character_set_to_upper[char];
        return if (possible_result != 0) possible_result else char;
    }
};

pub const ascii = @import("nls/ascii.zig");
