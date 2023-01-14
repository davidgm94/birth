const FAT32 = @This();

const host = @import("../../host.zig");

const lib = @import("../../lib.zig");
const kb = lib.kb;
const mb = lib.mb;
const gb = lib.gb;
const assert = lib.assert;

const Disk = lib.Disk;
const GPT = lib.PartitionTable.GPT;
const MBR = lib.PartitionTable.MBR;
const NLS = lib.NLS;
const log = lib.log.scoped(.FAT32);

pub const count = 2;
pub const volumes_lba = GPT.reserved_partition_size / GPT.max_block_size / 2;
pub const minimum_partition_size = 33 * mb;
pub const maximum_partition_size = 32 * gb;
pub const last_cluster = 0xffff_ffff;
pub const starting_cluster = 2;
pub const default_fs_info_sector = 1;
pub const default_backup_boot_record_sector = 6;
pub const default_reserved_sector_count = 32;

const NameCase = packed struct(u8) {
    reserved: u3 = 0,
    base: Case = .upper,
    extension: Case = .upper,
    reserved1: u3 = 0,
};
const Case = enum(u1) {
    upper = 0,
    lower = 1,
};

pub const FSInfo = extern struct {
    lead_signature: u32 = 0x41617272,
    reserved: [480]u8 = [1]u8{0} ** 480,
    signature: u32 = 0x61417272,
    free_cluster_count: u32,
    last_allocated_cluster: u32,
    reserved1: [12]u8 = [1]u8{0} ** 12,
    trail_signature: u32 = 0xaa550000,

    pub fn format(fsinfo: *const FSInfo, comptime _: []const u8, _: lib.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try lib.format(writer, "FSInfo:\n", .{});
        try lib.format(writer, "\tLead signature: 0x{x}\n", .{fsinfo.lead_signature});
        try lib.format(writer, "\tOther signature: 0x{x}\n", .{fsinfo.signature});
        try lib.format(writer, "\tFree cluster count: {}\n", .{fsinfo.free_cluster_count});
        try lib.format(writer, "\tLast allocated cluster: {}\n", .{fsinfo.last_allocated_cluster});
        try lib.format(writer, "\tTrail signature: 0x{x}\n", .{fsinfo.trail_signature});
    }
};

pub fn is_filesystem(file: []const u8) bool {
    const magic = "FAT32   ";
    return lib.equal(u8, file[0x52..], magic);
}

pub fn is_boot_record(file: []const u8) bool {
    const magic = [_]u8{ 0x55, 0xAA };
    const magic_alternative = [_]u8{ 'M', 'S', 'W', 'I', 'N', '4', '.', '1' };
    if (!lib.equal(u8, file[0x1fe..], magic)) return false;
    if (!lib.equal(u8, file[0x3fe..], magic)) return false;
    if (!lib.equal(u8, file[0x5fe..], magic)) return false;
    if (!lib.equal(u8, file[0x03..], magic_alternative)) return false;
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

pub const Date = packed struct(u16) {
    day: u5,
    month: u4,
    year: u7,

    pub fn new(day: u5, month: u4, year: u12) Date {
        return Date{
            .day = day,
            .month = month,
            .year = @intCast(u7, year - 1980),
        };
    }
};

pub const Time = packed struct(u16) {
    seconds_2_factor: u5,
    minutes: u6,
    hours: u5,

    pub fn new(seconds: u6, minutes: u6, hours: u5) Time {
        return Time{
            .seconds_2_factor = @intCast(u5, seconds / 2),
            .minutes = minutes,
            .hours = hours,
        };
    }
};

const max_base_len = 8;
const max_extension_len = 3;
const short_name_len = max_base_len + max_extension_len;
const long_name_max_characters = 255;

pub const DirectoryEntry = extern struct {
    name: [short_name_len]u8,
    attributes: Attributes,
    case: NameCase,
    creation_time_tenth: u8,
    creation_time: Time,
    creation_date: Date,
    last_access_date: Date,
    first_cluster_high: u16,
    last_write_time: Time,
    last_write_date: Date,
    first_cluster_low: u16,
    file_size: u32,

    pub const Sector = [per_sector]@This();
    pub const per_sector = @divExact(0x200, @sizeOf(@This()));

    pub const Chain = extern struct {
        previous: ?*DirectoryEntry = null,
        next: ?*DirectoryEntry = null,
        current: *DirectoryEntry,
    };

    pub fn format(entry: *const DirectoryEntry, comptime _: []const u8, _: lib.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try lib.format(writer, "Directory entry:\n", .{});
        try lib.format(writer, "\tName: {s}\n", .{entry.name});
        try lib.format(writer, "\tAttributes: {}\n", .{entry.attributes});
        try lib.format(writer, "\tCreation time tenth: {}\n", .{entry.creation_time_tenth});
        try lib.format(writer, "\tCreation time: {}\n", .{entry.creation_time});
        try lib.format(writer, "\tCreation date: {}\n", .{entry.creation_date});
        try lib.format(writer, "\tLast access date: {}\n", .{entry.last_access_date});
        try lib.format(writer, "\tLast write time: {}\n", .{entry.last_write_time});
        try lib.format(writer, "\tLast write date: {}\n", .{entry.last_write_date});
        const first_cluster = @as(u32, entry.first_cluster_high) << 16 | entry.first_cluster_low;
        try lib.format(writer, "\tFirst cluster: 0x{x}\n", .{first_cluster});
        try lib.format(writer, "\tFile size: 0x{x}\n", .{entry.file_size});
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

    pub fn set_first_cluster(entry: *DirectoryEntry, cluster: u32) void {
        entry.first_cluster_low = @truncate(u16, cluster);
        entry.first_cluster_high = @truncate(u16, cluster >> 16);
    }

    pub fn get_first_cluster(entry: *DirectoryEntry) u32 {
        return @as(u32, entry.first_cluster_high) << 16 | entry.first_cluster_low;
    }

    comptime {
        assert(@sizeOf(@This()) == 32);
    }
};

pub const Attributes = packed struct(u8) {
    read_only: bool = false,
    hidden: bool = false,
    system: bool = false,
    volume_id: bool = false,
    directory: bool = false,
    archive: bool = false,
    reserved: u2 = 0,

    pub fn has_long_name(attributes: Attributes) bool {
        return attributes.read_only and attributes.hidden and attributes.system and attributes.volume_id;
    }
};

pub const LongNameEntry = extern struct {
    sequence_number: packed struct(u8) {
        number: u5,
        first_physical_entry: u1 = 0,
        last_logical: bool,
        reserved: u1 = 0,
    },
    chars_0_4: [5]u16 align(1),
    attributes: Attributes,
    reserved: u8 = 0,
    checksum: u8,
    chars_5_10: [6]u16 align(1),
    first_cluster: u16 align(1),
    chars_11_12: [2]u16 align(1),

    pub const Sector = [per_sector]@This();
    pub const per_sector = @divExact(0x200, @sizeOf(@This()));

    pub fn is_last(entry: LongNameEntry) bool {
        return entry.sequence_number.last_logical;
    }

    fn get_characters(entry: LongNameEntry) [13]u16 {
        return entry.chars_0_4 ++ entry.chars_5_10 ++ entry.chars_11_12;
    }

    fn is_free(entry: LongNameEntry) bool {
        const first_char = entry.chars_0_4[0];
        assert(first_char != 0x20);
        return switch (first_char) {
            0, 0xe5, ' ' => true,
            else => false,
        };
    }
};

pub const Entry = packed struct(u32) {
    value: u28,
    reserved: u4 = 0,

    pub const Sector = [per_sector]FAT32.Entry;
    const per_sector = @divExact(0x200, @sizeOf(FAT32.Entry));

    pub fn is_free(entry: Entry) bool {
        return entry.value == value_free;
    }

    pub fn is_eof(entry: Entry, max_valid_cluster_number: u32) bool {
        return switch (entry.get_type(max_valid_cluster_number)) {
            .reserved_and_should_not_be_used_eof, .allocated_and_eof => true,
            .bad_cluster, .reserved_and_should_not_be_used, .allocated, .free => false,
        };
    }

    pub fn is_allocated_and_eof(entry: Entry) bool {
        return entry.value == value_allocated_and_eof;
    }

    pub fn get_type(entry: Entry, max_valid_cluster_number: u32) Type {
        return switch (entry.value) {
            value_free => .free,
            value_bad_cluster => .bad_cluster,
            value_reserved_and_should_not_be_used_eof_start...value_reserved_and_should_not_be_used_eof_end => .reserved_and_should_not_be_used_eof,
            value_allocated_and_eof => .allocated_and_eof,
            else => if (entry.value >= value_allocated_start and entry.value <= @intCast(u28, max_valid_cluster_number)) .allocated else if (entry.value >= @intCast(u28, max_valid_cluster_number) + 1 and entry.value <= value_reserved_and_should_not_be_used_end) .reserved_and_should_not_be_used else @panic("wtF"),
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

fn cdiv(a: u32, b: u32) u32 {
    return (a + b - 1) / b;
}

const min_cluster_32 = 65525;
const max_cluster_32 = 268435446;

pub fn format(disk: *Disk, partition_range: Disk.PartitionRange, copy_mbr: ?*const MBR.Partition) !Cache {
    if (disk.type != .memory) @panic("disk is not memory");
    const fat_partition_mbr_lba = partition_range.first_lba;
    const fat_partition_mbr = try disk.read_typed_sectors(MBR.Partition, fat_partition_mbr_lba, null, .{});

    const sectors_per_track = 32;
    const total_sector_count_32 = @intCast(u32, lib.alignBackward(partition_range.last_lba - partition_range.first_lba, sectors_per_track));
    const fat_count = FAT32.count;

    var cluster_size: u8 = 1;
    const max_cluster_size = 128;
    var fat_data_sector_count: u32 = undefined;
    var fat_length_32: u32 = undefined;
    var cluster_count_32: u32 = undefined;

    while (true) {
        assert(cluster_size > 0);
        fat_data_sector_count = total_sector_count_32 - lib.alignForwardGeneric(u32, FAT32.default_reserved_sector_count, cluster_size);
        cluster_count_32 = (fat_data_sector_count * disk.sector_size + fat_count * 8) / (cluster_size * disk.sector_size + fat_count * 4);
        fat_length_32 = lib.alignForwardGeneric(u32, cdiv((cluster_count_32 + 2) * 4, disk.sector_size), cluster_size);
        cluster_count_32 = (fat_data_sector_count - fat_count * fat_length_32) / cluster_size;
        const max_cluster_size_32 = @min(fat_length_32 * disk.sector_size / 4, max_cluster_32);
        if (cluster_count_32 > max_cluster_size_32) {
            cluster_count_32 = 0;
        }
        if (cluster_count_32 != 0 and cluster_count_32 < min_cluster_32) {
            cluster_count_32 = 0;
        }

        if (cluster_count_32 != 0) break;

        cluster_size <<= 1;

        const keep_going = cluster_size != 0 and cluster_size <= max_cluster_size;
        if (!keep_going) break;
        @panic("wtf");
    }

    var root_directory_entries: u64 = 0;
    _ = root_directory_entries;

    const reserved_sector_count = lib.alignForwardGeneric(u16, FAT32.default_reserved_sector_count, cluster_size);

    fat_partition_mbr.* = MBR.Partition{
        .bpb = .{
            .dos3_31 = .{
                .dos2_0 = .{
                    .jmp_code = .{ 0xeb, 0x58, 0x90 },
                    .oem_identifier = "mkfs.fat".*,
                    .sector_size = disk.sector_size,
                    .cluster_sector_count = cluster_size,
                    .reserved_sector_count = reserved_sector_count,
                    .fat_count = fat_count,
                    .root_entry_count = 0,
                    .total_sector_count_16 = 0,
                    .media_descriptor = 0xf8,
                    .fat_sector_count_16 = 0,
                },
                .physical_sectors_per_track = sectors_per_track,
                .disk_head_count = 8,
                .hidden_sector_count = @intCast(u32, partition_range.first_lba),
                .total_sector_count_32 = total_sector_count_32,
            },
            .fat_sector_count_32 = fat_length_32,
            .drive_description = 0,
            .version = .{ 0, 0 },
            .root_directory_cluster_offset = FAT32.starting_cluster,
            .fs_info_sector = FAT32.default_fs_info_sector,
            .backup_boot_record_sector = FAT32.default_backup_boot_record_sector,
            .drive_number = 0x80,
            .extended_boot_signature = 0x29,
            .serial_number = if (copy_mbr) |copy_partition_mbr| copy_partition_mbr.bpb.serial_number else @truncate(u32, @intCast(u64, host.time.microTimestamp())),
            .volume_label = "NO NAME    ".*,
            .filesystem_type = "FAT32   ".*,
        },
        .code = [_]u8{
            0xe, 0x1f, 0xbe, 0x77, 0x7c, 0xac, 0x22, 0xc0, 0x74, 0xb, 0x56, 0xb4, 0xe, 0xbb, 0x7, 0x0, 0xcd, 0x10, 0x5e, 0xeb, 0xf0, 0x32, 0xe4, 0xcd, 0x16, 0xcd, 0x19, 0xeb, 0xfe, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x61, 0x20, 0x62, 0x6f, 0x6f, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x64, 0x69, 0x73, 0x6b, 0x2e, 0x20, 0x20, 0x50, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x20, 0x69, 0x6e, 0x73, 0x65, 0x72, 0x74, 0x20, 0x61, 0x20, 0x62, 0x6f, 0x6f, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x66, 0x6c, 0x6f, 0x70, 0x70, 0x79, 0x20, 0x61, 0x6e, 0x64, 0xd, 0xa, 0x70, 0x72, 0x65, 0x73, 0x73, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x74, 0x6f, 0x20, 0x74, 0x72, 0x79, 0x20, 0x61, 0x67, 0x61, 0x69, 0x6e, 0x20, 0x2e, 0x2e, 0x2e, 0x20, 0xd, 0xa,
        } ++ [1]u8{0} ** 227,
        // This should be zero
        .partitions = lib.zeroes([4]MBR.LegacyPartition),
    };

    try disk.write_typed_sectors(MBR.Partition, fat_partition_mbr, fat_partition_mbr_lba, false);

    const backup_boot_record_sector = partition_range.first_lba + fat_partition_mbr.bpb.backup_boot_record_sector;
    const backup_boot_record = try disk.read_typed_sectors(MBR.Partition, backup_boot_record_sector, null, .{});
    backup_boot_record.* = fat_partition_mbr.*;
    try disk.write_typed_sectors(MBR.Partition, backup_boot_record, backup_boot_record_sector, false);

    const fs_info_lba = partition_range.first_lba + fat_partition_mbr.bpb.fs_info_sector;
    const fs_info = try disk.read_typed_sectors(FAT32.FSInfo, fs_info_lba, null, .{});
    fs_info.* = .{
        .lead_signature = 0x41615252,
        .signature = 0x61417272,
        .free_cluster_count = cluster_count_32,
        .last_allocated_cluster = 0,
        .trail_signature = 0xaa550000,
    };
    try disk.write_typed_sectors(FAT32.FSInfo, fs_info, fs_info_lba, false);

    const cache = Cache{
        .disk = disk,
        .partition_range = partition_range,
        .mbr = fat_partition_mbr,
        .fs_info = fs_info,
    };

    // TODO: write this properly

    try cache.register_cluster(0, FAT32.Entry.reserved_and_should_not_be_used_eof);
    try cache.register_cluster(1, FAT32.Entry.allocated_and_eof);
    try cache.register_cluster(2, FAT32.Entry.reserved_and_should_not_be_used_eof);

    cache.fs_info.last_allocated_cluster = 2;
    cache.fs_info.free_cluster_count = cluster_count_32 - 1;

    const backup_fs_info_lba = backup_boot_record_sector + backup_boot_record.bpb.fs_info_sector;
    const backup_fs_info = try disk.read_typed_sectors(FAT32.FSInfo, backup_fs_info_lba, null, .{});
    backup_fs_info.* = fs_info.*;
    try disk.write_typed_sectors(FAT32.FSInfo, backup_fs_info, backup_fs_info_lba, false);

    return cache;
}

fn write_fat_entry_slow(disk: *Disk, fat_partition_mbr: *MBR.Partition, partition_lba_start: u64, fat_entry: FAT32.Entry, fat_entry_index: usize) !void {
    const fat_entries_lba = partition_lba_start + fat_partition_mbr.bpb.dos3_31.dos2_0.reserved_sector_count;
    const fat_entry_count = fat_partition_mbr.bpb.dos3_31.dos2_0.fat_count;
    const fat_entry_sector_count = fat_partition_mbr.bpb.fat_sector_count_32;
    var fat_index: u8 = 0;

    while (fat_index < fat_entry_count) : (fat_index += 1) {
        const fat_entry_lba = fat_entries_lba + (fat_index * fat_entry_sector_count) + (fat_entry_index * @sizeOf(u32) / disk.sector_size);
        const fat_entry_sector = try disk.read_typed_sectors(FAT32.Entry.Sector, fat_entry_lba);
        const fat_entry_sector_index = fat_entry_index % disk.sector_size;
        fat_entry_sector[fat_entry_sector_index] = fat_entry;
        try disk.write_typed_sectors(FAT32.Entry.Sector, fat_entry_sector, fat_entry_lba, false);
    }
}

const dot_entry_name: [short_name_len]u8 = ".".* ++ ([1]u8{' '} ** 10);
const dot_dot_entry_name: [short_name_len]u8 = "..".* ++ ([1]u8{' '} ** 9);

pub const NameConfiguration = packed struct(u8) {
    display: Display,
    create: Create,
    reserved: u5 = 0,

    const Create = enum(u1) {
        windows_95 = 0,
        windows_nt = 1,
    };
    const Display = enum(u2) {
        lower = 0,
        windows_95 = 1,
        windows_nt = 2,
    };
};

const lower = NameConfiguration{ .display = .lower, .create = .windows_95 };
const windows_95 = NameConfiguration{ .display = .windows_95, .create = .windows_95 };
const windows_nt = NameConfiguration{ .display = .windows_nt, .create = .windows_nt };
const mixed = NameConfiguration{ .display = .windows_nt, .create = .windows_95 };

pub const Cache = extern struct {
    disk: *Disk,
    partition_range: Disk.PartitionRange,
    mbr: *MBR.Partition,
    fs_info: *FSInfo,
    name_configuration: NameConfiguration = mixed,

    fn get_backup_boot_record_sector(cache: Cache) u64 {
        return cache.partition_range.first_lba + cache.mbr.bpb.backup_boot_record_sector;
    }

    pub fn read_file(cache: Cache, allocator: ?*lib.Allocator, file_path: []const u8) ![]u8 {
        const directory_entry_result = try cache.get_directory_entry(file_path, allocator, null);
        const directory_entry =directory_entry_result.directory_entry; 
        const first_cluster = directory_entry.get_first_cluster();
        const file_size = directory_entry.file_size;
        const aligned_file_size = lib.alignForward(file_size, cache.disk.sector_size);
        const lba = cache.cluster_to_sector(first_cluster);
        return try cache.disk.read_slice(u8, aligned_file_size, lba, allocator, .{});
    }

    pub fn fromGPTPartitionCache(allocator: *lib.Allocator, gpt_partition_cache: GPT.Partition.Cache) !FAT32.Cache {
        const partition_range = Disk.PartitionRange{
            .first_lba = gpt_partition_cache.partition.first_lba,
            .last_lba = gpt_partition_cache.partition.last_lba,
        };
        const disk = gpt_partition_cache.gpt.disk;

        const partition_mbr = try disk.read_typed_sectors(MBR.Partition, partition_range.first_lba, allocator, .{});
        assert(partition_mbr.bpb.dos3_31.dos2_0.cluster_sector_count == 1);
        const fs_info_sector = partition_range.first_lba + partition_mbr.bpb.fs_info_sector;
        const fs_info = try disk.read_typed_sectors(FAT32.FSInfo, fs_info_sector, allocator, .{});

        return .{
            .disk = disk,
            .partition_range = partition_range,
            .mbr = partition_mbr,
            .fs_info = fs_info,
        };
    }

    pub fn reserve_directory_entries(cache: Cache, cluster: u32, entry_count: usize) !ReserveDirectoryEntries {
        const root_cluster = cache.get_root_cluster();
        const root_cluster_lba = cache.get_data_lba();
        const cluster_directory_entry_offset_lba = cache.get_cluster_sector_count() * (cluster - root_cluster);
        const cluster_directory_entry_lba = root_cluster_lba + cluster_directory_entry_offset_lba;
        const cluster_sector_count = cache.get_cluster_sector_count();
        assert(cluster_sector_count == 1);

        // TODO: what to do when there's more than one cluster per directory?
        const top_cluster_lba = cluster_directory_entry_lba + cluster_sector_count;
        var cluster_lba = cluster_directory_entry_lba;

        while (cluster_lba < top_cluster_lba) : (cluster_lba += 1) {
            const fat_directory_entries = try cache.disk.read_typed_sectors(DirectoryEntry.Sector, cluster_lba);

            for (fat_directory_entries) |*entry, entry_index| {
                if (entry.is_free()) {
                    const free_entries_in_sector = fat_directory_entries.len - entry_index;
                    assert(entry_count <= free_entries_in_sector);
                    return .{
                        .cluster_lba = cluster_lba,
                        .first_entry_index = entry_index,
                    };
                }
            }
        }

        return ReserveDirectoryEntries.Error.no_free_space;
    }

    const ReserveDirectoryEntries = extern struct {
        cluster_lba: u64,
        first_entry_index: usize,

        const Error = error{
            no_free_space,
        };
    };

    pub fn mkdir(cache: Cache, absolute_path: []const u8, copy_cache: ?Cache) !void {
        const directory_entry = try cache.get_directory_entry(absolute_path, .{ .allocate = .directory }, copy_cache);
        _ = directory_entry;
    }

    pub fn add_file(cache: Cache, absolute_path: []const u8, file_content: []const u8, copy_cache: ?FAT32.Cache) !void {
        const file_entry = try cache.get_directory_entry(absolute_path, .{ .allocate = .{ .file = .{ .content = file_content } } }, copy_cache);
        _ = file_entry;
    }

    pub const GetError = error{
        not_found,
        entry_already_exist,
    };

    pub fn write_directory_entry(cache: Cache, entry_to_write: anytype, cluster_lba: u64, entry_index: usize) !*@TypeOf(entry_to_write) {
        const EntryType = @TypeOf(entry_to_write);
        comptime assert(EntryType == DirectoryEntry or EntryType == LongNameEntry);
        comptime assert(@sizeOf(EntryType) == 32);

        const entries = try cache.disk.read_typed_sectors(EntryType.Sector, cluster_lba);
        const entry = &entries[entry_index];
        entry.* = entry_to_write;

        try cache.disk.write_typed_sectors(EntryType.Sector, entries, cluster_lba, false);

        return entry;
    }

    fn get_directory_entry_cluster(cache: Cache, dir: []const u8, allocator: ?*lib.Allocator) !u32 {
        if (lib.equal(u8, dir, "/")) {
            return cache.get_root_cluster();
        } else {
            const containing_dir_entry = try cache.get_directory_entry(dir, allocator, null);
            return containing_dir_entry.directory_entry.get_first_cluster();
        }
    }

    pub fn make_new_directory(cache: Cache, absolute_path: []const u8, allocator: ?*lib.Allocator, copy_cache: ?FAT32.Cache) !void {
        const copy_entry: ?*DirectoryEntry = if (copy_cache) |my_copy_cache| (try my_copy_cache.get_directory_entry(absolute_path, allocator, null)).directory_entry else null;
        const last_slash_index = lib.lastIndexOf(u8, absolute_path, "/") orelse @panic("wtf");
        const containing_dir = absolute_path[0..if (last_slash_index == 0) 1 else last_slash_index];
        const containing_dir_cluster = try cache.get_directory_entry_cluster(containing_dir, allocator);
        const content_cluster = try cache.allocate_new_directory(containing_dir_cluster, allocator, copy_cache);
        const last_element = absolute_path[last_slash_index + 1 ..];
        try cache.add_entry(.{ .name = last_element, .is_dir = true, .content_cluster = content_cluster, .containing_cluster = containing_dir_cluster }, allocator, copy_entry);
    }

    pub fn create_file(cache: Cache, file_path: []const u8, file_content: []const u8, allocator: ?*lib.Allocator, copy_cache: ?FAT32.Cache) !void {
        const copy_entry: ?*DirectoryEntry = if (copy_cache) |my_copy_cache| (try my_copy_cache.get_directory_entry(file_path, null, null)).directory_entry else null;
        const last_slash_index = lib.lastIndexOf(u8, file_path, "/") orelse @panic("wtf");
        const containing_dir = file_path[0..if (last_slash_index == 0) 1 else last_slash_index];
        const containing_dir_cluster = try cache.get_directory_entry_cluster(containing_dir, allocator);
        const content_cluster = try cache.allocate_new_file(file_content, allocator);
        const last_element = file_path[last_slash_index + 1 ..];
        try cache.add_entry(.{ .name = last_element, .size = @intCast(u32, file_content.len), .is_dir = false, .content_cluster = content_cluster, .containing_cluster = containing_dir_cluster }, allocator, copy_entry);
    }

    fn allocate_new_file(cache: Cache, file_content: []const u8, maybe_allocator: ?*lib.Allocator) !u32 {
        assert(file_content.len > 0);
        const cluster_byte_count = cache.get_cluster_sector_count() * cache.disk.sector_size;
        const aligned_file_size = lib.alignForward(file_content.len, cluster_byte_count);
        const cluster_count = @divExact(aligned_file_size, cluster_byte_count);
        const allocator = maybe_allocator orelse @panic("We need an allocator");
        const clusters = blk: {
            const alloc_result = try allocator.allocateBytes(@sizeOf(u32) * cluster_count, @alignOf(u32));
            break :blk @intToPtr([*]u32, alloc_result.address)[0..cluster_count];
        };
        log.debug("Cluster count: {}", .{cluster_count});
        try cache.allocate_clusters(clusters, allocator);

        for (clusters) |cluster, cluster_index| {
            const cluster_byte_offset = cluster_byte_count * cluster_index;
            const slice_start = cluster_byte_offset;
            const slice_end = cluster_byte_offset + cluster_byte_count;
            const slice = file_content[slice_start..if (slice_end > file_content.len) file_content.len else slice_end];
            const lba = cache.cluster_to_sector(cluster);
            log.debug("slice start: 0x{x}. slice end: 0x{x}. cluster: 0x{x}. lba: 0x{x}. slice len: {}. disk size: 0x{x}", .{slice_start, slice_end, cluster, lba, slice.len, cache.disk.disk_size});
            try cache.disk.write_slice(u8, slice, lba, true);
        }

        return clusters[0];
    }

    const Size = struct {
        len: u16,
        size: u16,
    };

    fn translate_to_unicode(name: []const u8, buffer: []u16) !Size {
        // Using always UTF8
        const len = try lib.unicode.utf8ToUtf16Le(buffer, name);
        var size = len;
        if (size % character_count_per_long_entry != 0) {
            buffer[size] = 0;
            size += 1;
            const remainder = size % character_count_per_long_entry;
            if (remainder != 0) {
                const characters_to_fill = character_count_per_long_entry - remainder;

                for (buffer[size .. size + characters_to_fill]) |*wide_char| {
                    wide_char.* = lib.maxInt(u16);
                }

                size += characters_to_fill;
            }
        }

        return .{ .len = @intCast(u16, len), .size = @intCast(u16, size) };
    }

    const BadChar = error{
        bad_value,
        last_character_space,
    };

    fn check_bad_chars(string: []u16) !void {
        for (string) |wchar| {
            if (wchar < 0x20 or wchar == '*' or wchar == '?' or wchar == '<' or wchar == '>' or wchar == '|' or wchar == '"' or wchar == ':' or wchar == '/' or wchar == '\\') return BadChar.bad_value;
        }

        if (string[string.len - 1] == ' ') return BadChar.last_character_space;
    }

    fn is_skip_char(wchar: u16) bool {
        return wchar == '.' or wchar == ' ';
    }

    fn is_replace_char(wchar: u16) bool {
        return wchar == '[' or wchar == ']' or wchar == ';' or wchar == ',' or wchar == '+' or wchar == '=';
    }

    const ShortNameInfo = packed struct(u8) {
        len: u5 = 0,
        lower: bool = true,
        upper: bool = true,
        valid: bool = true,
    };

    fn to_shortname_char(nls: *const NLS.Table, wchar: u16, char_buffer: []u8) !ShortNameInfo {
        var is_lower = true;
        var is_upper = true;
        var is_valid = true;

        if (is_skip_char(wchar)) @panic("wtf");
        if (is_replace_char(wchar)) @panic("wtf");

        try nls.unicode_to_character(wchar, char_buffer);

        // TODO:
        const len = 1;
        if (len == 0) {
            @panic("wtf");
        } else if (len == 1) {
            const previous = char_buffer[0];

            if (previous >= 0x7f) @panic("wtf");

            char_buffer[0] = nls.to_upper(previous);
            if (lib.isAlphabetic(char_buffer[0])) {
                if (char_buffer[0] == previous) {
                    is_lower = false;
                } else {
                    is_upper = false;
                }
            }
        } else @panic("wtf");

        return ShortNameInfo{
            .len = @intCast(u5, len),
            .lower = is_lower,
            .upper = is_upper,
            .valid = is_valid,
        };
    }

    const ShortNameResult = extern struct {
        name: [short_name_len]u8,
        case: NameCase,
    };

    fn create_shortname(cache: Cache, nls: *const NLS.Table, long_name: []u16, cluster: u32, short_name_result: *ShortNameResult, allocator: ?*lib.Allocator) !bool {
        var is_short_name = true;
        const end = lib.ptrAdd(u16, &long_name[0], long_name.len);
        var extension_start: ?*u16 = end;
        var size: usize = 0;

        while (true) {
            extension_start = lib.maybePtrSub(u16, extension_start, 1);
            if (@ptrToInt(extension_start) < @ptrToInt(&long_name[0])) break;

            if (extension_start.?.* == '.') {
                if (extension_start == lib.ptrSub(u16, end, 1)) {
                    size = long_name.len;
                    extension_start = null;
                }

                break;
            }
        }

        if (extension_start == lib.ptrSub(u16, &long_name[0], 1)) {
            size = long_name.len;
            extension_start = null;
        } else if (extension_start) |ext_start| {
            const extension_start_index = @ptrToInt(ext_start) - @ptrToInt(&long_name[0]);
            const index = blk: {
                const slice = long_name[0..extension_start_index];

                for (slice) |wchar, index| {
                    if (!is_skip_char(wchar)) break :blk index;
                }

                break :blk slice.len;
            };

            if (index != extension_start_index) {
                size = extension_start_index;
                extension_start = lib.maybePtrAdd(u16, extension_start, 1);
            } else {
                size = long_name.len;
                extension_start = null;
            }
        }

        var numtail_base_len: usize = 6;
        var numtail2_base_len: usize = 2;

        var char_buffer: [NLS.max_charset_size]u8 = undefined;
        var base: [9]u8 = undefined;
        var long_name_index: usize = 0;
        var base_len: usize = 0;
        var pointer_it: usize = 0;
        var base_info = ShortNameInfo{};
        var extension_info = ShortNameInfo{};

        while (long_name_index < size) : ({
            long_name_index += 1;
        }) {
            const wchar = long_name[long_name_index];
            // TODO: chl
            // TODO: shortname_info
            base_info = try to_shortname_char(nls, wchar, &char_buffer);

            const chl = 1;
            if (chl == 0) continue;

            if (base_len < 2 and (base_len + chl) > 2) {
                numtail2_base_len = base_len;
            }

            if (base_len < 6 and (base_len + chl) > 6) {
                numtail_base_len = base_len;
            }

            var char_index: usize = 0;
            while (char_index < chl) : ({
                char_index += 1;
            }) {
                const char = char_buffer[char_index];
                base[pointer_it] = char;
                pointer_it += 1;
                base_len += 1;
                if (base_len >= 8) break;
            }

            if (base_len >= 8) {
                if ((char_index < chl - 1) or (long_name_index + 1) < size) {
                    is_short_name = false;
                }
                break;
            }
        }

        if (base_len == 0) @panic("wtf");

        var extension_len: usize = 0;
        var extension: [4]u8 = undefined;
        if (extension_start) |ext_start| {
            _ = ext_start;
            @panic("wtf");
        }

        extension[extension_len] = 0;
        base[base_len] = 0;

        if (base[0] == 0xe5) base[0] = 0x05;

        short_name_result.* = ShortNameResult{
            .name = blk: {
                var name = [1]u8{' '} ** short_name_len;
                lib.copy(u8, name[0..base_len], base[0..base_len]);
                lib.copy(u8, name[max_base_len .. max_base_len + extension_len], extension[0..extension_len]);
                break :blk name;
            },
            .case = .{ .base = .upper, .extension = .upper },
        };

        if (is_short_name and base_info.valid and extension_info.valid) {
            if (try cache.exists(&short_name_result.name, cluster, allocator)) @panic("wtf");
            const result = switch (cache.name_configuration.create) {
                .windows_95 => base_info.upper and extension_info.upper,
                .windows_nt => @panic("wtf"),
            };
            return result;
        }

        @panic("wtf");
    }

    pub fn scan(cache: Cache, name: []const u8, cluster: u32, allocator: ?*lib.Allocator) !?*DirectoryEntry {
        var iterator = DirectoryEntryIterator(DirectoryEntry).init(cluster);

        while (try iterator.next(cache, allocator)) |entry| {
            assert(!entry.attributes.has_long_name());
            if (lib.equal(u8, &entry.name, name)) {
                return entry;
            }
        }

        return null;
    }

    pub fn exists(cache: Cache, name: []const u8, cluster: u32, allocator: ?*lib.Allocator) !bool {
        return (try cache.scan(name, cluster, allocator)) != null;
    }

    const GenericEntry = struct {
        long_name_entries: []LongNameEntry = &.{},
        normal_entry: DirectoryEntry,

        pub fn is_extended(entry: GenericEntry) bool {
            return entry.long_name_entries.len != 0;
        }

        pub fn get_slots(entry: GenericEntry) usize {
            return entry.long_name_entries.len + 1;
        }
    };

    pub fn add_entry(cache: Cache, entry_setup: struct { name: []const u8, size: u32 = 0, content_cluster: u32, containing_cluster: u32, is_dir: bool }, maybe_allocator: ?*lib.Allocator, copy_entry: ?*DirectoryEntry) !void {
        // TODO:
        for (entry_setup.name) |ch| {
            if (ch == '.') @panic("todo: unexpected dot in fat32 entry");
        }

        var long_name_array = [1]u16{0} ** (long_name_max_characters + 2);
        const size = try translate_to_unicode(entry_setup.name, &long_name_array);
        const long_name = long_name_array[0..size.len];
        try check_bad_chars(long_name);

        var short_name_result: ShortNameResult = undefined;
        const can_get_away_with_short_name = try cache.create_shortname(&NLS.ascii.table, long_name, entry_setup.content_cluster, &short_name_result, maybe_allocator);
        // TODO: timestamp
        const timestamp = host.time.milliTimestamp();
        _ = timestamp;
        var entry = GenericEntry{
            .normal_entry = DirectoryEntry{
                .name = short_name_result.name,
                .attributes = .{
                    .directory = entry_setup.is_dir,
                    .archive = !entry_setup.is_dir,
                },
                .case = short_name_result.case,
                .creation_time_tenth = if (copy_entry) |e| e.creation_time_tenth else 0,
                .creation_time = if (copy_entry) |e| e.creation_time else .{
                    .seconds_2_factor = 0,
                    .minutes = 0,
                    .hours = 0,
                },
                .creation_date = if (copy_entry) |e| e.creation_date else .{
                    .day = 0,
                    .month = 0,
                    .year = 0,
                },
                .last_access_date = if (copy_entry) |e| e.last_access_date else .{
                    .day = 0,
                    .month = 0,
                    .year = 0,
                },
                .first_cluster_high = @truncate(u16, entry_setup.content_cluster >> 16),
                .last_write_time = if (copy_entry) |e| e.last_write_time else .{
                    .seconds_2_factor = 0,
                    .minutes = 0,
                    .hours = 0,
                },
                .last_write_date = if (copy_entry) |e| e.last_write_date else .{
                    .day = 0,
                    .month = 0,
                    .year = 0,
                },
                .first_cluster_low = @truncate(u16, entry_setup.content_cluster),
                .file_size = entry_setup.size,
            },
        };

        if (!can_get_away_with_short_name) {
            const checksum = shortname_checksum(&short_name_result.name);

            const long_slot_count = @intCast(u5, size.size / character_count_per_long_entry);
            entry.long_name_entries = blk: {
                const allocator = maybe_allocator orelse @panic("WTF allocator");
                const alloc_result = try allocator.allocateBytes(@intCast(usize, @sizeOf(LongNameEntry)) * long_slot_count, @alignOf(LongNameEntry));
                break :blk @intToPtr([*]LongNameEntry, alloc_result.address)[0..long_slot_count];
            };
            var reverse_index = long_slot_count;

            for (entry.long_name_entries) |*long_name_entry| {
                const offset = (reverse_index - 1) * character_count_per_long_entry;
                long_name_entry.* = .{
                    .sequence_number = .{
                        .number = reverse_index,
                        .last_logical = reverse_index == long_slot_count,
                    },
                    .chars_0_4 = long_name_array[offset .. offset + 6][0..5].*,
                    .attributes = .{
                        .read_only = true,
                        .hidden = true,
                        .system = true,
                        .volume_id = true,
                    },
                    .checksum = checksum,
                    .chars_5_10 = long_name_array[offset + 5 .. offset + 11][0..6].*,
                    .first_cluster = 0,
                    .chars_11_12 = long_name_array[offset + 11 .. offset + 13][0..2].*,
                };
            }
        }

        const total_slots = entry.get_slots();
        var free_slots: usize = 0;
        var entry_iterator = DirectoryEntryIterator(DirectoryEntry).init(entry_setup.containing_cluster);
        var current_cluster: u32 = 0;

        while (try entry_iterator.next(cache, maybe_allocator)) |cluster_entry| {
            if (cluster_entry.is_free()) {
                if (free_slots == 0) current_cluster = @intCast(u32, entry_iterator.cluster);
                free_slots += 1;

                if (free_slots == total_slots) {
                    const last_current_cluster = @intCast(u32, entry_iterator.cluster);
                    assert(last_current_cluster == current_cluster);
                    const element_offset = @divExact(@ptrToInt(cluster_entry) - @ptrToInt(&entry_iterator.cluster_entries[0]), @sizeOf(DirectoryEntry));
                    log.debug("Element offset: {}. Free slots: {}", .{ element_offset, free_slots });
                    const entry_start_index = element_offset - (free_slots - 1);
                    log.debug("Entry start index: {}", .{entry_start_index});

                    var entry_index = entry_start_index;
                    for (entry.long_name_entries) |*long_name_entry| {
                        entry_iterator.cluster_entries[entry_index] = @bitCast(DirectoryEntry, long_name_entry.*);
                        entry_index += 1;
                    }

                    entry_iterator.cluster_entries[entry_index] = entry.normal_entry;

                    try cache.disk.write_slice(DirectoryEntry, entry_iterator.cluster_entries, entry_iterator.get_current_lba(cache), false);

                    return;
                }
            } else {
                free_slots = 0;
            }
        }

        @panic("wtf");
    }

    pub fn shortname_checksum(name: []const u8) u8 {
        var result = name[0];

        result = (result << 7) + (result >> 1) +% name[1];
        result = (result << 7) + (result >> 1) +% name[2];
        result = (result << 7) + (result >> 1) +% name[3];
        result = (result << 7) + (result >> 1) +% name[4];
        result = (result << 7) + (result >> 1) +% name[5];
        result = (result << 7) + (result >> 1) +% name[6];
        result = (result << 7) + (result >> 1) +% name[7];
        result = (result << 7) + (result >> 1) +% name[8];
        result = (result << 7) + (result >> 1) +% name[9];
        result = (result << 7) + (result >> 1) +% name[10];

        return result;
    }

    pub fn allocate_new_directory(cache: Cache, containing_cluster: u32, provided_buffer: ?[]const u8, copy_cache: ?FAT32.Cache) !u32 {
        var clusters = [1]u32{0};
        try cache.allocate_clusters(&clusters, provided_buffer);
        const cluster = clusters[0];
        const lba = cache.cluster_to_sector(cluster);
        log.debug("Directory cluster LBA: 0x{x}", .{lba});
        const fat_directory_entries = try cache.disk.read_typed_sectors(FAT32.DirectoryEntry.Sector, lba, provided_buffer);

        var copy_entry: ?*FAT32.DirectoryEntry = null;
        if (copy_cache) |cp_cache| {
            const entries = try cp_cache.disk.read_typed_sectors(FAT32.DirectoryEntry.Sector, cp_cache.cluster_to_sector(cluster), null);
            copy_entry = &entries[0];
        }
        const attributes = Attributes{
            .read_only = false,
            .hidden = false,
            .system = false,
            .volume_id = false,
            .directory = true,
            .archive = false,
        };
        fat_directory_entries[0] = FAT32.DirectoryEntry{
            .name = dot_entry_name,
            .attributes = attributes,
            .case = .{},
            .creation_time_tenth = if (copy_entry) |ce| ce.creation_time_tenth else @panic("wtf"),
            .creation_time = if (copy_entry) |ce| ce.creation_time else @panic("wtf"),
            .creation_date = if (copy_entry) |ce| ce.creation_date else @panic("wtf"),
            .first_cluster_high = @truncate(u16, cluster >> 16),
            .first_cluster_low = @truncate(u16, cluster),
            .last_access_date = if (copy_entry) |ce| ce.last_access_date else @panic("wtf"),
            .last_write_time = if (copy_entry) |ce| ce.last_write_time else @panic("wtf"),
            .last_write_date = if (copy_entry) |ce| ce.last_write_date else @panic("wtf"),
            .file_size = 0,
        };
        // Copy the values and only modify the necessary ones
        fat_directory_entries[1] = fat_directory_entries[0];
        fat_directory_entries[1].name = dot_dot_entry_name;
        // TODO: Fix this
        fat_directory_entries[1].set_first_cluster(if (containing_cluster == cache.get_root_cluster()) 0 else containing_cluster);
        if (copy_entry) |cp_entry| {
            const copy_cluster = cp_entry.get_first_cluster();
            const dot_entry_cluster = fat_directory_entries[0].get_first_cluster();
            const dot_dot_entry_cluster = fat_directory_entries[1].get_first_cluster();
            log.debug("Copy cluster: {}", .{copy_cluster});
            log.debug("Dot cluster: {}", .{dot_entry_cluster});
            log.debug("Dot dot cluster: {}", .{dot_dot_entry_cluster});
        }

        // TODO: zero initialize the unused part of the cluster
        try cache.disk.write_typed_sectors(FAT32.DirectoryEntry.Sector, fat_directory_entries, lba, false);

        return cluster;
    }

    pub inline fn cluster_to_sector(cache: Cache, cluster: u32) u64 {
        return (@as(u64, cluster) - cache.get_root_cluster()) * cache.get_cluster_sector_count() + cache.get_data_lba();
    }

    fn register_cluster(cache: Cache, cluster: u32, entry: Entry) !void {
        const fat_lba = cache.get_fat_lba();
        const fat_entry_count = cache.mbr.bpb.dos3_31.dos2_0.fat_count;
        const fat_entry_sector_count = cache.mbr.bpb.fat_sector_count_32;

        if (entry.is_allocated_and_eof()) {
            cache.fs_info.last_allocated_cluster = cluster;
            cache.fs_info.free_cluster_count -= 1;
        }

        // Actually allocate FAT entry

        var fat_index: u8 = 0;

        const fat_entry_sector_index = cluster % FAT32.Entry.per_sector;

        const cluster_offset = cluster * @sizeOf(u32) / cache.disk.sector_size;
        while (fat_index < fat_entry_count) : (fat_index += 1) {
            const fat_entry_lba = fat_lba + (fat_index * fat_entry_sector_count) + cluster_offset;
            const fat_entry_sector = try cache.disk.read_typed_sectors(FAT32.Entry.Sector, fat_entry_lba, null, .{});
            fat_entry_sector[fat_entry_sector_index] = entry;
            log.debug("Registering cluster 0x{x} with FAT entry LBA 0x{x} and fat entry sector index 0x{x}", .{cluster, fat_entry_lba, fat_entry_sector_index});
            try cache.disk.write_typed_sectors(FAT32.Entry.Sector, fat_entry_sector, fat_entry_lba, false);
        }
    }

    pub fn allocate_clusters(cache: Cache, clusters: []u32, maybe_allocator: ?*lib.Allocator) !void {
        var fat_entry_iterator = try FATEntryIterator.init(cache, maybe_allocator);
        var cluster_index: usize = 0;

        while (try fat_entry_iterator.next(cache, maybe_allocator)) |cluster| {
            const entry = &fat_entry_iterator.entries[cluster % Entry.per_sector];
            if (entry.is_free()) {
                try cache.register_cluster(cluster, FAT32.Entry.allocated_and_eof);
                clusters[cluster_index] = cluster;
                cluster_index += 1;

                if (cluster_index == clusters.len) return;
            }
        }

        @panic("wtf");
    }

    pub fn get_directory_entry(cache: Cache, absolute_path: []const u8, allocator: ?*lib.Allocator, copy_cache: ?Cache) !EntryResult(DirectoryEntry) {
        const fat_lba = cache.partition_range.first_lba + cache.mbr.bpb.dos3_31.dos2_0.reserved_sector_count;
        const root_cluster = cache.mbr.bpb.root_directory_cluster_offset;
        const data_lba = fat_lba + (cache.mbr.bpb.fat_sector_count_32 * cache.mbr.bpb.dos3_31.dos2_0.fat_count);

        const root_cluster_sector = data_lba;
        var upper_cluster = root_cluster;
        var dir_tokenizer = lib.DirectoryTokenizer.init(absolute_path);
        var directories: usize = 0;

        const first_dir = dir_tokenizer.next() orelse @panic("wtf");
        assert(lib.equal(u8, first_dir, "/"));

        entry_loop: while (dir_tokenizer.next()) |entry_name| : (directories += 1) {
            const is_last = dir_tokenizer.is_last();
            log.debug("Searching for entry #{}: {s} in absolute path: {s}. Last: {}", .{ directories, entry_name, absolute_path, is_last });

            const copy_entry: ?*FAT32.DirectoryEntry = blk: {
                if (copy_cache) |cc| {
                    const name = absolute_path[0..dir_tokenizer.index];
                    log.debug("Entry name: {s}", .{name});
                    const entry_result = try cc.get_directory_entry(name, allocator, null);
                    break :blk entry_result.directory_entry;
                } else break :blk null;
            };
            _ = copy_entry;

            const normalized_name = pack_string(entry_name, .{
                .len = short_name_len,
                .fill_with = ' ',
                .upper = true,
            });

            while (true) : (upper_cluster += 1) {
                const cluster_sector_offset = root_cluster_sector + cache.get_cluster_sector_count() * (upper_cluster - root_cluster);
                const directory_entries_in_cluster = try cache.disk.read_typed_sectors(DirectoryEntry.Sector, cluster_sector_offset, allocator, .{});

                var entry_index: usize = 0;
                while (entry_index < directory_entries_in_cluster.len) : ({
                    entry_index += 1;
                }) {
                    const directory_entry = &directory_entries_in_cluster[entry_index];
                    const is_empty = directory_entry.name[0] == 0;
                    const is_unused = directory_entry.name[0] == 0xe5;
                    const is_long_name = directory_entry.attributes.has_long_name();

                    // At this point all entries in the given directory have been checked, so it's safe to say the directory doesn't contain the wanted entry
                    if (is_empty) {
                        return GetError.not_found;
                    } else {
                        if (is_unused) {
                            @panic("wtf");
                        } else if (is_long_name) {
                            const long_name_entry = @ptrCast(*FAT32.LongNameEntry, directory_entry);
                            const original_starting_index = entry_index;

                            if (long_name_entry.is_last()) {
                                entry_index += 1;
                                assert(entry_index < directory_entries_in_cluster.len);
                                const long_name_u16 = long_name_entry.get_characters();
                                var arr: [long_name_u16.len]u8 = [1]u8{0} ** long_name_u16.len;
                                const long_name_u8 = blk: {
                                    for (long_name_u16) |u16_ch, index| {
                                        log.debug("[{}]: {u}", .{ index, u16_ch });
                                        if (u16_ch == 0) {
                                            break :blk arr[0..index];
                                        } else if (u16_ch <= lib.maxInt(u8)) {
                                            arr[index] = @intCast(u8, u16_ch);
                                        } else {
                                            @panic("wtf");
                                        }
                                    }

                                    @panic("wtf");
                                };

                                log.debug("Long name \"{s}\" ({}). Entry name \"{s}\"({})", .{ long_name_u8, long_name_u8.len, entry_name, entry_name.len });
                                // TODO: compare long name entry
                                if (lib.equal(u8, long_name_u8, entry_name)) {
                                    const normal_entry = &directory_entries_in_cluster[entry_index];
                                    if (is_last) {
                                        return .{ .cluster = upper_cluster, .entry_starting_index = @intCast(u32, original_starting_index), .directory_entry = normal_entry };
                                    } else {
                                        upper_cluster = normal_entry.get_first_cluster();
                                        continue :entry_loop;
                                    }
                                }
                            } else {
                                @panic("wtf");
                            }
                        } else {
                            if (lib.equal(u8, &directory_entry.name, &normalized_name)) {
                                if (is_last) {
                                    return .{ .cluster = upper_cluster, .entry_starting_index = @intCast(u32, entry_index), .directory_entry = directory_entry };
                                } else {
                                    upper_cluster = directory_entry.get_first_cluster();
                                    continue :entry_loop;
                                }
                            }
                        }
                    }
                }

                return GetError.not_found;
            }
        }

        @panic("wtf");
    }

    pub fn get_fat_lba(cache: Cache) u64 {
        const fat_lba = cache.partition_range.first_lba + cache.mbr.bpb.dos3_31.dos2_0.reserved_sector_count;
        return fat_lba;
    }

    pub fn get_data_lba(cache: Cache) u64 {
        const data_lba = cache.get_fat_lba() + (cache.mbr.bpb.fat_sector_count_32 * cache.mbr.bpb.dos3_31.dos2_0.fat_count);
        return data_lba;
    }

    pub fn get_root_cluster(cache: Cache) u32 {
        const root_cluster = cache.mbr.bpb.root_directory_cluster_offset;
        return root_cluster;
    }

    pub fn allocate_file_content(cache: Cache, file_content: []const u8) !u32 {
        const sector_count = @intCast(u32, @divExact(lib.alignForward(file_content.len, cache.disk.sector_size), cache.disk.sector_size));
        const cluster_count = lib.alignForwardGeneric(u32, sector_count, cache.get_cluster_sector_count());
        assert(cluster_count == 1);
        @panic("wtf");
        //const first_cluster = try cache.
        //try cache.write_string_to_cluster_offset(file_content, first_cluster);
        //return first_cluster;
    }

    pub fn write_string_to_cluster_offset(cache: Cache, string: []const u8, cluster_offset: u32) !void {
        const data_lba = cache.get_data_lba();
        const root_cluster = cache.get_root_cluster();
        const sector_offset = data_lba + cache.cluster_to_sectors(cluster_offset - root_cluster);
        try cache.disk.write_slice(u8, string, sector_offset, true);
    }

    pub inline fn get_cluster_sector_count(cache: Cache) u32 {
        return cache.mbr.bpb.dos3_31.dos2_0.cluster_sector_count;
    }
};

const PackStringOptions = packed struct(u64) {
    fill_with: u8,
    len: u8,
    upper: bool,
    reserved: u47 = 0,
};

pub inline fn pack_string(name: []const u8, comptime options: PackStringOptions) [options.len]u8 {
    var result = [1]u8{options.fill_with} ** options.len;
    if (name.len > 0) {
        if (options.upper) {
            _ = lib.upperString(&result, name);
        } else {
            lib.copy(u8, &result, name);
        }
    }

    return result;
}

const character_count_per_long_entry = 13;
pub inline fn long_name_chop(name: []const u8, comptime start: usize, comptime end: usize) [end - start + 1]u16 {
    const len = end - start + 1;
    const string = if (start > name.len) "" else if (end > name.len) name[start..] else name[start..end];
    var result = [1]u16{lib.maxInt(u16)} ** len;
    if (string.len > 0) {
        for (string) |character, index| {
            const ptr = &result[index];
            ptr.* = @as(u16, character);
        }

        if (string.len < len) {
            result[string.len] = 0;
        }
    }

    return result;
}

fn EntryResult(comptime EntryType: type) type {
    return extern struct {
        entry_starting_index: usize,
        directory_entry: *EntryType,
        cluster: u32,
    };
}

// Sadly we have to wrap shell commands into scripts because of shell redirection usages
const LoopbackDevice = struct {
    name: []const u8,
    mount_dir: ?[]const u8 = null,

    fn start(loopback_device: LoopbackDevice, allocator: lib.ZigAllocator, image_path: []const u8) !void {
        try host.spawnProcess(&.{ "./tools/loopback_start.sh", image_path, loopback_device.name }, allocator);
    }

    fn end(loopback_device: LoopbackDevice, allocator: lib.ZigAllocator) !void {
        assert(loopback_device.mount_dir == null);
        try host.spawnProcess(&.{ "./tools/loopback_end.sh", loopback_device.name }, allocator);
        try host.cwd().deleteFile(loopback_device.name);
    }

    fn mount(loopback_device: *LoopbackDevice, allocator: lib.ZigAllocator, mount_dir: []const u8) !MountedPartition {
        try host.cwd().makePath(mount_dir);
        try host.spawnProcess(&.{ "./tools/loopback_mount.sh", loopback_device.name, mount_dir }, allocator);
        loopback_device.mount_dir = mount_dir;

        return MountedPartition{
            .loopback_device = loopback_device.*,
        };
    }
};

const MountedPartition = struct {
    loopback_device: LoopbackDevice,

    fn mkdir(partition: MountedPartition, allocator: lib.ZigAllocator, dir: []const u8) !void {
        try host.spawnProcess(&.{ "sudo", "mkdir", "-p", try partition.join_with_root(allocator, dir) }, allocator);
    }

    fn join_with_root(partition: MountedPartition, allocator: lib.ZigAllocator, path: []const u8) ![]const u8 {
        const mount_dir = partition.get_mount_dir();
        const slices_to_join: []const []const u8 = if (path[0] == '/') &.{ mount_dir, path } else &.{ mount_dir, "/", path };
        const joint_path = try lib.concat(allocator, u8, slices_to_join);
        return joint_path;
    }

    pub fn get_mount_dir(partition: MountedPartition) []const u8 {
        const mount_dir = partition.loopback_device.mount_dir orelse @panic("wtf");
        return mount_dir;
    }

    fn copy_file(partition: MountedPartition, allocator: lib.ZigAllocator, file_path: []const u8, file_content: []const u8) !void {
        log.debug("Making sure path is created...", .{});
        const last_slash_index = lib.lastIndexOf(u8, file_path, "/") orelse @panic("wtf");
        const file_name = file_path[last_slash_index + 1 ..];
        assert(file_name.len > 0);
        try host.cwd().writeFile(file_name, file_content);
        const dir = file_path[0..if (last_slash_index == 0) 1 else last_slash_index];
        log.debug("Creating path to {s}", .{dir});
        const destination_dir = try partition.join_with_root(allocator, dir);
        const mkdir_process_args = &.{ "sudo", "mkdir", "-p", destination_dir };
        try host.spawnProcess(mkdir_process_args, allocator);
        log.debug("Copying file...", .{});
        const copy_process_args = &.{ "sudo", "cp", "-v", file_name, destination_dir };
        try host.spawnProcess(copy_process_args, allocator);
        try host.cwd().deleteFile(file_name);
    }

    fn end(partition: *MountedPartition, allocator: lib.ZigAllocator) !void {
        const mount_dir = partition.loopback_device.mount_dir orelse @panic("wtf");
        host.sync();
        try host.spawnProcess(&.{ "sudo", "umount", mount_dir }, allocator);
        partition.loopback_device.mount_dir = null;
        try partition.loopback_device.end(allocator);
        host.spawnProcess(&.{ "sudo", "rm", "-rf", mount_dir }, allocator) catch |err| {
            switch (err) {
                host.ExecutionError.failed => {},
                else => return err,
            }
        };
    }
};

const FATEntryIterator = struct {
    entries: []FAT32.Entry = &.{},
    cluster: u32,

    fn init(cache: Cache, allocator: ?*lib.Allocator) !FATEntryIterator {
        const cluster = cache.fs_info.last_allocated_cluster + 1;
        assert(cache.disk.sector_size == @sizeOf(FAT32.Entry.Sector));
        const lba_offset = cache.get_fat_lba() + (cluster / FAT32.Entry.per_sector);

        return .{
            .entries = try cache.disk.read_typed_sectors(FAT32.Entry.Sector, lba_offset, allocator, .{}),
            .cluster = cluster,
        };
    }

    fn next(iterator: *FATEntryIterator, cache: Cache, allocator: ?*lib.Allocator) !?u32 {
        var cluster_count: usize = starting_cluster;
        // TODO: replace with proper variable
        const max_clusters = 100000;
        if (cache.disk.sector_size != @sizeOf(FAT32.Entry.Sector)) @panic("WTF");

        while (cluster_count < max_clusters) {
            if (cluster_count >= max_clusters) cluster_count = starting_cluster;

            if (iterator.cluster != 0 and iterator.cluster % iterator.entries.len == 0) {
                iterator.cluster += 1;
                const lba_offset = cache.get_fat_lba() + (iterator.cluster / FAT32.Entry.per_sector);
                iterator.entries = try cache.disk.read_typed_sectors(FAT32.Entry.Sector, lba_offset, allocator, .{});
            }

            const result = iterator.cluster;
            iterator.cluster += 1;
            return result;
        }

        @panic("wtf");
    }
};

fn DirectoryEntryIterator(comptime EntryType: type) type {
    assert(EntryType == DirectoryEntry or EntryType == LongNameEntry);

    return struct {
        cluster_entries: []EntryType = &.{},
        cluster_it: u32 = 0,
        cluster: u32,
        cluster_fetched: bool = false,

        const Iterator = @This();

        pub fn init(cluster: u32) Iterator {
            return Iterator{
                .cluster = cluster,
            };
        }

        pub fn get_current_lba(iterator: *Iterator, cache: Cache) u64 {
            const cluster_lba = cache.cluster_to_sector(iterator.cluster);
            return cluster_lba;
        }

        pub fn next(iterator: *Iterator, cache: Cache, allocator: ?*lib.Allocator) !?*EntryType {
            if (iterator.cluster_fetched) iterator.cluster_it += 1;

            const cluster_sector_count = cache.get_cluster_sector_count();
            const cluster_entry_count = @divExact(cluster_sector_count * cache.disk.sector_size, @sizeOf(EntryType));
            assert(iterator.cluster_it <= cluster_entry_count);
            if (iterator.cluster_it == cluster_entry_count) return null; // TODO: Should we early return like this?

            if (!iterator.cluster_fetched or iterator.cluster_it == cluster_entry_count) {
                if (iterator.cluster_it == cluster_entry_count) iterator.cluster += 1;

                const cluster_lba = cache.cluster_to_sector(iterator.cluster);
                iterator.cluster_entries = try cache.disk.read_slice(EntryType, cluster_entry_count, cluster_lba, allocator, .{});
                iterator.cluster_it = 0;
                iterator.cluster_fetched = true;
            }

            return &iterator.cluster_entries[iterator.cluster_it];
        }
    };
}

test "Basic FAT32 image" {
    lib.testing.log_level = .debug;

    switch (lib.os) {
        .linux => {
            const original_image_path = "barebones.hdd";
            const sector_count = 131072;
            const sector_size = 0x200;
            const partition_start_lba = 0x800;
            const partition_name = "ESP";
            const partition_filesystem = lib.Filesystem.Type.fat32;

            // Using an arena allocator because it doesn't care about memory leaks
            var arena_allocator = host.ArenaAllocator.init(host.page_allocator);
            defer arena_allocator.deinit();

            var wrapped_allocator = lib.Allocator.wrap(arena_allocator.allocator());

            var disk_image = try Disk.Image.fromZero(sector_count, sector_size);
            defer host.cwd().deleteFile(original_image_path) catch @panic("wtf");

            const directories = [_][]const u8{ "/EFI", "/EFI/BOOT", "/EFI/BOOT/FOO" };
            const files = [_]struct { path: []const u8, content: []const u8 }{
                .{ .path = "/foo", .content = "this is the foo file content" },
                .{ .path = "/EFI/def", .content = "this is the def file content" },
                .{ .path = "/EFI/BOOT/xyz", .content = "this is the xyz file content" },
                .{ .path = "/EFI/opq", .content = "this is the opq file content" },
            };

            // 1. Test GPT creation
            var original_disk_image = blk: {
                const megabytes = @divExact(sector_count * sector_size, mb);
                try host.spawnProcess(&.{ "dd", "if=/dev/zero", "bs=1M", "count=0", try lib.allocPrint(wrapped_allocator.unwrap_zig(), "seek={d}", .{megabytes}), try lib.allocPrint(wrapped_allocator.unwrap_zig(), "of={s}", .{original_image_path}) }, wrapped_allocator.unwrap_zig());

                try host.spawnProcess(&.{ "parted", "-s", original_image_path, "mklabel", "gpt" }, wrapped_allocator.unwrap_zig());
                try host.spawnProcess(&.{ "parted", "-s", original_image_path, "mkpart", partition_name, @tagName(partition_filesystem), try lib.allocPrint(wrapped_allocator.unwrap_zig(), "{d}s", .{partition_start_lba}), "100%" }, wrapped_allocator.unwrap_zig());
                try host.spawnProcess(&.{ "parted", "-s", original_image_path, "set", "1", "esp", "on" }, wrapped_allocator.unwrap_zig());

                var loopback_device = LoopbackDevice{ .name = "loopback_device" };
                try loopback_device.start(wrapped_allocator.unwrap_zig(), original_image_path);

                try host.spawnProcess(&.{ "./tools/format_loopback_fat32.sh", loopback_device.name }, wrapped_allocator.unwrap_zig());

                const mount_dir = "image_mount";

                var partition = try loopback_device.mount(wrapped_allocator.unwrap_zig(), mount_dir);

                for (directories) |directory| {
                    try partition.mkdir(wrapped_allocator.unwrap_zig(), directory);
                }

                for (files) |file| {
                    try partition.copy_file(wrapped_allocator.unwrap_zig(), file.path, file.content);
                }

                try partition.end(wrapped_allocator.unwrap_zig());

                break :blk try Disk.Image.fromFile(original_image_path, sector_size, wrapped_allocator.unwrap_zig());
            };

            const original_gpt_cache = try GPT.Partition.Cache.fromPartitionIndex(&original_disk_image.disk, 0, wrapped_allocator.unwrap());
            const original_fat_cache = try FAT32.Cache.from_gpt_partition_cache(wrapped_allocator.unwrap(), original_gpt_cache, null);

            const gpt_cache = try GPT.create(&disk_image.disk, original_gpt_cache.gpt.header);
            const gpt_partition_cache = try gpt_cache.addPartition(partition_filesystem, lib.unicode.utf8ToUtf16LeStringLiteral(partition_name), partition_start_lba, gpt_cache.header.last_usable_lba, original_gpt_cache.partition);
            const fat_partition_cache = try gpt_partition_cache.format(partition_filesystem, wrapped_allocator.unwrap(), original_fat_cache);

            for (directories) |directory| {
                try fat_partition_cache.make_new_directory(directory, null, original_fat_cache);
            }

            for (files) |file| {
                log.debug("Commanding to add file {s}", .{file.path});
                try fat_partition_cache.create_file(file.path, file.content, null, original_fat_cache);
            }

            try lib.diff(original_disk_image.get_buffer(), disk_image.get_buffer());
            try lib.testing.expectEqualSlices(u8, original_disk_image.get_buffer(), disk_image.get_buffer());
        },
        else => log.debug("Skipping for missing `parted` dependency...", .{}),
    }
}
