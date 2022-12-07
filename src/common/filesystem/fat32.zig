const common = @import("../../common.zig");
const assert = common.assert;
const Disk = common.Disk.Descriptor;
const GPT = common.PartitionTable.GPT;
const MBR = common.PartitionTable.MBR;
const kb = common.kb;
const mb = common.mb;
const gb = common.gb;
const log = common.log.scoped(.FAT32);

pub const count = 2;
pub const volumes_lba = GPT.reserved_partition_size / GPT.max_block_size / 2;
pub const minimum_partition_size = 33 * mb;
pub const maximum_partition_size = 32 * gb;
pub const last_cluster = 0xffff_ffff;
pub const starting_cluster = 2;
pub const fs_info_sector = 1;
pub const backup_boot_record_sector = 6;
pub const reserved_sector_count = 32;

pub const FSInfo = extern struct {
    lead_signature: u32 = 0x41617272,
    reserved: [480]u8 = [1]u8{0} ** 480,
    signature: u32 = 0x61417272,
    free_cluster_count: u32,
    next_free_cluster: u32,
    reserved1: [12]u8 = [1]u8{0} ** 12,
    trail_signature: u32 = 0xaa550000,

    pub fn format(fsinfo: *const FSInfo, comptime _: []const u8, _: common.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try common.internal_format(writer, "FSInfo:\n", .{});
        try common.internal_format(writer, "\tLead signature: 0x{x}\n", .{fsinfo.lead_signature});
        try common.internal_format(writer, "\tOther signature: 0x{x}\n", .{fsinfo.signature});
        try common.internal_format(writer, "\tFree cluster count: {}\n", .{fsinfo.free_cluster_count});
        try common.internal_format(writer, "\tNext free cluster: {}\n", .{fsinfo.next_free_cluster});
        try common.internal_format(writer, "\tTrail signature: 0x{x}\n", .{fsinfo.trail_signature});
    }
};

pub fn is_filesystem(file: []const u8) bool {
    const magic = "FAT32   ";
    return common.std.mem.eql(u8, file[0x52..], magic);
}

pub fn is_boot_record(file: []const u8) bool {
    const magic = [_]u8{ 0x55, 0xAA };
    const magic_alternative = [_]u8{ 'M', 'S', 'W', 'I', 'N', '4', '.', '1' };
    if (!common.std.mem.eql(u8, file[0x1fe..], magic)) return false;
    if (!common.std.mem.eql(u8, file[0x3fe..], magic)) return false;
    if (!common.std.mem.eql(u8, file[0x5fe..], magic)) return false;
    if (!common.std.mem.eql(u8, file[0x03..], magic_alternative)) return false;
    return true;
}

pub fn get_cluster_size(size: u64) u16 {
    if (size <= 64 * mb) return 0x200;
    if (size <= 128 * mb) return 1 * kb;
    if (size <= 256 * mb) return 2 * kb;
    if (size <= 8 * gb) return 8 * kb;
    if (size <= 16 * gb) return 16 * kb;

    return 32 * kb;
}

pub fn compute_cluster_sector_count(total_size: u64, sector_size: u16) u8 {
    return @intCast(u8, @divExact(get_cluster_size(total_size), sector_size));
}

pub const DirectoryEntry = extern struct {
    name: [11]u8,
    attributes: Attributes,
    nt_reserved: u8 = 0,
    creation_time_tenth: u8,
    creation_time: u16,
    creation_date: u16,
    last_access_date: u16,
    first_cluster_high: u16,
    last_write_time: u16,
    last_write_date: u16,
    first_cluster_low: u16,
    file_size: u32,

    pub const Attributes = packed struct(u8) {
        read_only: bool,
        hidden: bool,
        system: bool,
        volume_id: bool,
        directory: bool,
        archive: bool,
        reserved: u2 = 0,

        pub fn has_long_name(attributes: Attributes) bool {
            return attributes.read_only and attributes.hidden and attributes.system and attributes.volume_id;
        }
    };

    pub fn small_filename_only(entry: *const DirectoryEntry) bool {
        return !entry.attributes.has_long_name() and entry.name[0] != 0;
    }

    comptime {
        assert(@sizeOf(@This()) == 32);
    }
};

pub const Entry = packed struct(u32) {
    value: Value,
    reserved: u4 = 0,

    const Value = enum(u28) {
        free = 0,
        reserved = 0xfff_fff8,
        allocated = 0xfff_ffff,
    };

    pub const free = Entry{ .value = .free };
    pub const reserved = Entry{ .value = .reserved };
    pub const allocated = Entry{ .value = .allocated };
};
