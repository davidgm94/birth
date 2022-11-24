const std = @import("std");

pub fn is_filesystem(file: []const u8) bool {
    const magic = "FAT32   ";
    return std.mem.eql(u8, file[0x52..], magic);
}

pub fn is_boot_record(file: []const u8) bool {
    const magic = [_]u8{ 0x55, 0xAA };
    const magic_alternative = [_]u8{ 'M', 'S', 'W', 'I', 'N', '4', '.', '1' };
    if (!std.mem.eql(u8, file[0x1fe..], magic)) return false;
    if (!std.mem.eql(u8, file[0x3fe..], magic)) return false;
    if (!std.mem.eql(u8, file[0x5fe..], magic)) return false;
    if (!std.mem.eql(u8, file[0x03..], magic_alternative)) return false;
    return true;
}
