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
    last_allocated_cluster: u32,
    reserved1: [12]u8 = [1]u8{0} ** 12,
    trail_signature: u32 = 0xaa550000,

    pub inline fn allocate(fs_info: *FSInfo, cluster_count: u32) void {
        fs_info.last_allocated_cluster += cluster_count;
        fs_info.free_cluster_count -= cluster_count;
    }

    pub fn format(fsinfo: *const FSInfo, comptime _: []const u8, _: common.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try common.internal_format(writer, "FSInfo:\n", .{});
        try common.internal_format(writer, "\tLead signature: 0x{x}\n", .{fsinfo.lead_signature});
        try common.internal_format(writer, "\tOther signature: 0x{x}\n", .{fsinfo.signature});
        try common.internal_format(writer, "\tFree cluster count: {}\n", .{fsinfo.free_cluster_count});
        try common.internal_format(writer, "\tLast allocated cluster: {}\n", .{fsinfo.last_allocated_cluster});
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

    pub fn format(entry: *const DirectoryEntry, comptime _: []const u8, _: common.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try common.internal_format(writer, "Directory entry:\n", .{});
        try common.internal_format(writer, "\tName: {s}\n", .{entry.name});
        try common.internal_format(writer, "\tAttributes: {}\n", .{entry.attributes});
        try common.internal_format(writer, "\tCreation time tenth: {}\n", .{entry.creation_time_tenth});
        try common.internal_format(writer, "\tCreation time: {}\n", .{entry.creation_time});
        try common.internal_format(writer, "\tCreation date: {}\n", .{entry.creation_date});
        try common.internal_format(writer, "\tLast access date: {}\n", .{entry.last_access_date});
        try common.internal_format(writer, "\tLast write time: {}\n", .{entry.last_write_time});
        try common.internal_format(writer, "\tLast write date: {}\n", .{entry.last_write_date});
        const first_cluster = @as(u32, entry.first_cluster_high) << 16 | entry.first_cluster_low;
        try common.internal_format(writer, "\tFirst cluster: 0x{x}\n", .{first_cluster});
        try common.internal_format(writer, "\tFile size: 0x{x}\n", .{entry.file_size});
    }

    pub fn small_filename_only(entry: DirectoryEntry) bool {
        return !entry.attributes.has_long_name() and entry.name[0] != 0;
    }

    pub fn is_free(entry: DirectoryEntry) bool {
        const first_char = entry.name[0];
        assert(first_char != 0x20);
        return switch (first_char) {
            0, 0xe5, ' ' => true,
            else => false,
        };
    }

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

    comptime {
        assert(@sizeOf(@This()) == 32);
    }
};

pub const Entry = packed struct(u32) {
    value: u28,
    reserved: u4 = 0,

    pub fn is_free(entry: Entry) bool {
        return entry.value == value_free;
    }

    pub fn is_eof(entry: Entry, max_valid_cluster_number: u32) bool {
        return switch (entry.get_type(max_valid_cluster_number)) {
            .reserved_and_should_not_be_used_eof, .allocated_and_eof => true,
            .bad_cluster, .reserved_and_should_not_be_used, .allocated, .free => false,
        };
    }

    pub fn allocate(entry: *Entry) void {
        entry.* = get_entry(.allocated);
    }

    pub fn get_type(entry: Entry, max_valid_cluster_number: u32) Type {
        return switch (entry.value) {
            value_free => .free,
            value_bad_cluster => .bad_cluster,
            value_reserved_and_should_not_be_used_eof_start...value_reserved_and_should_not_be_used_eof_end => .reserved_and_should_not_be_used_eof,
            value_allocated_and_eof => .allocated_and_eof,
            else => if (entry.value >= value_allocated_start and entry.value <= @intCast(u28, max_valid_cluster_number)) .allocated else if (entry.value >= @intCast(u28, max_valid_cluster_number) + 1 and entry.value <= value_reserved_and_should_not_be_used_end) .reserved_and_should_not_be_used else unreachable,
        };
    }

    fn get_entry(t: Type) Entry {
        return Entry{
            .value = switch (t) {
                .free => value_free,
                .allocated => value_allocated_start,
                .reserved_and_should_not_be_used => value_reserved_and_should_not_be_used_end,
                .bad_cluster => value_bad_cluster,
                .reserved_and_should_not_be_used_eof => value_reserved_and_should_not_be_used_eof_start,
                .allocated_and_eof => value_allocated_and_eof,
            },
        };
    }

    pub const free = get_entry(.free);
    pub const allocated = get_entry(.allocated);
    pub const reserved_and_should_not_be_used = get_entry(.reserved_and_should_not_be_used);
    pub const bad_cluster = get_entry(.bad_cluster);
    pub const reserved_and_should_not_be_used_eof = get_entry(.reserved_and_should_not_be_used_eof);
    pub const allocated_and_eof = get_entry(.allocated_and_eof);

    const value_free = 0;
    const value_allocated_start = 2;
    const value_reserved_and_should_not_be_used_end = 0xfff_fff6;
    const value_bad_cluster = 0xfff_fff7;
    const value_reserved_and_should_not_be_used_eof_start = 0xfff_fff8;
    const value_reserved_and_should_not_be_used_eof_end = 0xfff_fffe;
    const value_allocated_and_eof = 0xfff_ffff;

    pub const Type = enum {
        free,
        allocated,
        reserved_and_should_not_be_used,
        bad_cluster,
        reserved_and_should_not_be_used_eof,
        allocated_and_eof,
    };
};

pub fn get_data_sector_count(mbr: *const MBR.Struct) u32 {
    const fat_sector_count = mbr.bpb.fat_sector_count_32;
    const total_sector_count = mbr.bpb.dos3_31.total_sector_count_32;
    const fat_count = mbr.bpb.dos3_31.dos2_0.fat_count;
    const reserved_sectors = mbr.bpb.dos3_31.dos2_0.reserved_sector_count;

    return total_sector_count - (reserved_sectors + (fat_count * fat_sector_count));
}

pub fn get_cluster_count(mbr: *const MBR.Struct) u32 {
    const data_sector_count = get_data_sector_count(mbr);
    const cluster_sector_count = mbr.bpb.dos3_31.dos2_0.cluster_sector_count;

    const cluster_count = @divExact(data_sector_count, cluster_sector_count);
    return cluster_count;
}

pub fn get_maximum_valid_cluster_number(mbr: *const MBR.Struct) u32 {
    return get_cluster_count(mbr) + 1;
}
