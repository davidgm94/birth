const std = @import("std");

pub const sector_size = 0x200;

pub const Superblock = struct {
    size: u64,
    files_offset: u64,
    files_size: u64,
    metadata_offset: u64,
    metadata_size: u64,

    pub fn init(bytes: []u8) void {
        const superblock = Superblock.get(bytes);
        const disk_size = bytes.len;
        superblock.size = disk_size;
        superblock.files_offset = std.mem.alignForward(@sizeOf(Superblock), sector_size);
        superblock.files_size = 0;
        superblock.metadata_offset = disk_size / 6;
        superblock.metadata_size = 0;
    }

    pub fn get(bytes: []u8) *Superblock {
        const superblock = @ptrCast(*Superblock, @alignCast(@alignOf(Superblock), bytes.ptr));
        return superblock;
    }
};

pub const FileEntry = struct {
    offset: u64,
    size: u64,

    const NameLengthType = u16;
    fn get_name(self: *@This()) []u8 {
        const name_base = @ptrToInt(self) + @sizeOf(FileEntry);
        const name_len = @intToPtr(*NameLengthType, name_base).*;
        const name = @intToPtr([*]u8, name_base + @sizeOf(NameLengthType))[0..name_len];
        return name;
    }

    fn set_name(self: *@This(), name: []const u8) void {
        const name_base = @ptrToInt(self) + @sizeOf(FileEntry);
        @intToPtr(*NameLengthType, name_base).* = name.len;
        std.mem.copy(u8, self.get_name(), 
    }
};

pub fn add_file(bytes: []u8, file: []const u8, filename: []const u8) void {
    const superblock = Superblock.get(bytes);
    const metadata_offset = superblock.metadata_offset + superblock.metadata_size;
    const file_slice = bytes[file_offset..file_offset + file.len];
    std.mem.copy(u8, file_slice, file);
}
