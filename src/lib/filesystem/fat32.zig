const FAT32 = @This();

const lib = @import("lib");
const log = lib.log;
const kb = lib.kb;
const mb = lib.mb;
const gb = lib.gb;
const assert = lib.assert;

const Disk = lib.Disk;
const GPT = lib.PartitionTable.GPT;
const MBR = lib.PartitionTable.MBR;
const NLS = lib.NLS;

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

pub fn isFilesystem(file: []const u8) bool {
    const magic = "FAT32   ";
    return lib.equal(u8, file[0x52..], magic);
}

pub fn isBootRecord(file: []const u8) bool {
    const magic = [_]u8{ 0x55, 0xAA };
    const magic_alternative = [_]u8{ 'M', 'S', 'W', 'I', 'N', '4', '.', '1' };
    if (!lib.equal(u8, file[0x1fe..], magic)) return false;
    if (!lib.equal(u8, file[0x3fe..], magic)) return false;
    if (!lib.equal(u8, file[0x5fe..], magic)) return false;
    if (!lib.equal(u8, file[0x03..], magic_alternative)) return false;
    return true;
}

pub fn getClusterSize(size: u64) u16 {
    if (size <= 64 * mb) return lib.default_sector_size;
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
            .year = @as(u7, @intCast(year - 1980)),
        };
    }
};

pub const Time = packed struct(u16) {
    seconds_2_factor: u5,
    minutes: u6,
    hours: u5,

    pub fn new(seconds: u6, minutes: u6, hours: u5) Time {
        return Time{
            .seconds_2_factor = @as(u5, @intCast(seconds / 2)),
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
    pub const per_sector = @divExact(lib.default_sector_size, @sizeOf(@This()));

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

    pub fn isFree(entry: DirectoryEntry) bool {
        const first_char = entry.name[0];
        assert(first_char != 0x20);
        return switch (first_char) {
            0, 0xe5, ' ' => true,
            else => false,
        };
    }

    pub fn setFirstCluster(entry: *DirectoryEntry, cluster: u32) void {
        entry.first_cluster_low = @as(u16, @truncate(cluster));
        entry.first_cluster_high = @as(u16, @truncate(cluster >> 16));
    }

    pub fn getFirstCluster(entry: *DirectoryEntry) u32 {
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

    pub fn hasLongName(attributes: Attributes) bool {
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
    pub const per_sector = @divExact(lib.default_sector_size, @sizeOf(@This()));

    pub fn isLast(entry: LongNameEntry) bool {
        return entry.sequence_number.last_logical;
    }

    fn getCharacters(entry: LongNameEntry) [13]u16 {
        return entry.chars_0_4 ++ entry.chars_5_10 ++ entry.chars_11_12;
    }

    fn isFree(entry: LongNameEntry) bool {
        const first_char = entry.chars_0_4[0];
        assert(first_char != 0x20);
        return switch (first_char) {
            0, 0xe5, ' ' => true,
            else => false,
        };
    }
};

pub const Entry = packed struct(u32) {
    next_cluster: u28,
    reserved: u4 = 0,

    pub const Sector = [per_sector]FAT32.Entry;
    const per_sector = @divExact(lib.default_sector_size, @sizeOf(FAT32.Entry));

    pub fn isFree(entry: Entry) bool {
        return entry.next_cluster == value_free;
    }

    pub fn isAllocating(entry: Entry) bool {
        return entry.next_cluster == value_allocated_and_eof or (entry.next_cluster >= value_allocated_start and entry.next_cluster < value_reserved_and_should_not_be_used_end);
    }

    pub fn getType(entry: Entry, max_valid_cluster_number: u32) Type {
        return switch (entry.value) {
            value_free => .free,
            value_bad_cluster => .bad_cluster,
            value_reserved_and_should_not_be_used_eof_start...value_reserved_and_should_not_be_used_eof_end => .reserved_and_should_not_be_used_eof,
            value_allocated_and_eof => .allocated_and_eof,
            else => if (entry.value >= value_allocated_start and entry.value <= @as(u28, @intCast(max_valid_cluster_number))) .allocated else if (entry.value >= @as(u28, @intCast(max_valid_cluster_number)) + 1 and entry.value <= value_reserved_and_should_not_be_used_end) .reserved_and_should_not_be_used else @panic("fat32: getType unexpected error"),
        };
    }

    fn getEntry(t: Type) Entry {
        return Entry{
            .next_cluster = switch (t) {
                .free => value_free,
                .allocated => value_allocated_start,
                .reserved_and_should_not_be_used => value_reserved_and_should_not_be_used_end,
                .bad_cluster => value_bad_cluster,
                .reserved_and_should_not_be_used_eof => value_reserved_and_should_not_be_used_eof_start,
                .allocated_and_eof => value_allocated_and_eof,
            },
        };
    }

    pub const free = getEntry(.free);
    pub const allocated = getEntry(.allocated);
    pub const reserved_and_should_not_be_used = getEntry(.reserved_and_should_not_be_used);
    pub const bad_cluster = getEntry(.bad_cluster);
    pub const reserved_and_should_not_be_used_eof = getEntry(.reserved_and_should_not_be_used_eof);
    pub const allocated_and_eof = getEntry(.allocated_and_eof);

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

pub fn getMinCluster(comptime filesystem: lib.FilesystemType) comptime_int {
    return switch (filesystem) {
        .fat32 => 65525,
        else => @compileError("Filesystem not supported"),
    };
}

pub fn getMaxCluster(comptime filesystem: lib.FilesystemType) comptime_int {
    return switch (filesystem) {
        .fat32 => 268435446,
        else => @compileError("Filesystem not supported"),
    };
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
    allocator: ?*lib.Allocator,

    fn get_backup_boot_record_sector(cache: Cache) u64 {
        return cache.partition_range.first_lba + cache.mbr.bpb.backup_boot_record_sector;
    }

    pub fn readFile(cache: Cache, allocator: ?*lib.Allocator, file_path: []const u8) ![]u8 {
        const directory_entry_result = try cache.getDirectoryEntry(file_path, null);
        const directory_entry = directory_entry_result.directory_entry;
        const first_cluster = directory_entry.getFirstCluster();
        const file_size = directory_entry.file_size;
        const aligned_file_size = lib.alignForward(file_size, cache.disk.sector_size);
        const lba = cache.clusterToSector(first_cluster);
        const result = try cache.disk.readSlice(u8, aligned_file_size, lba, allocator, .{});
        return result[0..file_size];
    }

    pub fn readFileToBuffer(cache: Cache, file_path: []const u8, file_buffer: []u8) ![]u8 {
        const directory_entry_result = try cache.getDirectoryEntry(file_path, null);
        const directory_entry = directory_entry_result.directory_entry;
        const first_cluster = directory_entry.getFirstCluster();
        const file_size = directory_entry.file_size;
        const aligned_file_size = lib.alignForward(usize, file_size, cache.disk.sector_size);
        const lba = cache.clusterToSector(first_cluster);

        log.debug("Start disk callback", .{});

        const result = try cache.disk.callbacks.read(cache.disk, @divExact(aligned_file_size, cache.disk.sector_size), lba, file_buffer);
        log.debug("End disk callback", .{});
        return result.buffer[0..file_size];
    }

    pub fn readFileToCache(cache: Cache, file_path: []const u8, size: usize) ![]const u8 {
        const directory_entry_result = try cache.getDirectoryEntry(file_path, null);
        const directory_entry = directory_entry_result.directory_entry;
        const first_cluster = directory_entry.getFirstCluster();
        const file_size = directory_entry.file_size;
        const lba = cache.clusterToSector(first_cluster);

        const read_size = @min(file_size, size);
        const aligned_read_size = lib.alignForward(usize, read_size, cache.disk.sector_size);

        const result = try cache.disk.callbacks.readCache(cache.disk, @divExact(aligned_read_size, cache.disk.sector_size), lba);
        const result_slice = result.buffer[0..read_size];
        return result_slice;
    }

    pub fn getFileSize(cache: Cache, file_path: []const u8) !u32 {
        const directory_entry_result = try cache.getDirectoryEntry(file_path, null);
        return directory_entry_result.directory_entry.file_size;
    }

    pub fn fromGPTPartitionCache(allocator: *lib.Allocator, gpt_partition_cache: GPT.Partition.Cache) !FAT32.Cache {
        const partition_range = Disk.PartitionRange{
            .first_lba = gpt_partition_cache.partition.first_lba,
            .last_lba = gpt_partition_cache.partition.last_lba,
        };
        const disk = gpt_partition_cache.gpt.disk;

        const partition_mbr = try disk.readTypedSectors(MBR.Partition, partition_range.first_lba, allocator, .{});
        assert(partition_mbr.bpb.dos3_31.dos2_0.cluster_sector_count == 1);
        const fs_info_sector = partition_range.first_lba + partition_mbr.bpb.fs_info_sector;
        const fs_info = try disk.readTypedSectors(FAT32.FSInfo, fs_info_sector, allocator, .{});

        return .{
            .disk = disk,
            .partition_range = partition_range,
            .mbr = partition_mbr,
            .fs_info = fs_info,
            .allocator = allocator,
        };
    }

    pub fn reserveDirectoryEntries(cache: Cache, cluster: u32, entry_count: usize) !ReserveDirectoryEntries {
        const root_cluster = cache.get_root_cluster();
        const root_cluster_lba = cache.get_data_lba();
        const cluster_directory_entry_offset_lba = cache.getClusterSectorCount() * (cluster - root_cluster);
        const cluster_directory_entry_lba = root_cluster_lba + cluster_directory_entry_offset_lba;
        const cluster_sector_count = cache.getClusterSectorCount();
        assert(cluster_sector_count == 1);

        // TODO: what to do when there's more than one cluster per directory?
        const top_cluster_lba = cluster_directory_entry_lba + cluster_sector_count;
        var cluster_lba = cluster_directory_entry_lba;

        while (cluster_lba < top_cluster_lba) : (cluster_lba += 1) {
            const fat_directory_entries = try cache.disk.readTypedSectors(DirectoryEntry.Sector, cluster_lba);

            for (fat_directory_entries, 0..) |*entry, entry_index| {
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

    pub const GetError = error{
        not_found,
        entry_already_exist,
    };

    fn getDirectoryEntryCluster(cache: Cache, dir: []const u8) !u32 {
        if (lib.equal(u8, dir, "/")) {
            return cache.getRootCluster();
        } else {
            const containing_dir_entry = try cache.getDirectoryEntry(dir, null);
            return containing_dir_entry.directory_entry.getFirstCluster();
        }
    }

    pub fn makeNewDirectory(cache: Cache, absolute_path: []const u8, allocator: ?*lib.Allocator, copy_cache: ?FAT32.Cache, miliseconds: u64) !void {
        const copy_entry: ?*DirectoryEntry = if (copy_cache) |my_copy_cache| (try my_copy_cache.getDirectoryEntry(absolute_path, null)).directory_entry else null;
        const last_slash_index = lib.lastIndexOf(u8, absolute_path, "/") orelse @panic("there must be a slash");
        const containing_dir = absolute_path[0..if (last_slash_index == 0) 1 else last_slash_index];
        const containing_dir_cluster = try cache.getDirectoryEntryCluster(containing_dir);
        const content_cluster = try cache.allocateNewDirectory(containing_dir_cluster, allocator, copy_cache);
        const last_element = absolute_path[last_slash_index + 1 ..];
        try cache.addEntry(.{ .name = last_element, .is_dir = true, .content_cluster = content_cluster, .containing_cluster = containing_dir_cluster }, allocator, copy_entry, miliseconds);
    }

    pub fn makeNewFile(cache: Cache, file_path: []const u8, file_content: []const u8, allocator: ?*lib.Allocator, copy_cache: ?FAT32.Cache, milliseconds: u64) !void {
        const copy_entry: ?*DirectoryEntry = if (copy_cache) |my_copy_cache| (try my_copy_cache.getDirectoryEntry(file_path, null)).directory_entry else null;
        const last_slash_index = lib.lastIndexOf(u8, file_path, "/") orelse @panic("there must be a slash");
        const containing_dir = file_path[0..if (last_slash_index == 0) 1 else last_slash_index];
        const containing_dir_cluster = try cache.getDirectoryEntryCluster(containing_dir);
        const content_cluster = try cache.allocateNewFile(file_content, allocator);
        const file_name = file_path[last_slash_index + 1 ..];
        try cache.addEntry(.{ .name = file_name, .size = @as(u32, @intCast(file_content.len)), .is_dir = false, .content_cluster = content_cluster, .containing_cluster = containing_dir_cluster }, allocator, copy_entry, milliseconds);
    }

    fn allocateNewFile(cache: Cache, file_content: []const u8, maybe_allocator: ?*lib.Allocator) !u32 {
        assert(file_content.len > 0);
        const cluster_byte_count = cache.getClusterSectorCount() * cache.disk.sector_size;
        const aligned_file_size = lib.alignForward(usize, file_content.len, cluster_byte_count);
        const cluster_count = @divExact(aligned_file_size, cluster_byte_count);
        // log.debug("Need to allocate {} clusters for file", .{cluster_count});
        const allocator = maybe_allocator orelse @panic("We need an allocator");
        const clusters = blk: {
            const alloc_result = try allocator.allocateBytes(@sizeOf(u32) * cluster_count, @alignOf(u32));
            break :blk @as([*]u32, @ptrFromInt(alloc_result.address))[0..cluster_count];
        };
        try cache.allocateClusters(clusters, allocator);

        for (clusters, 0..) |cluster, cluster_index| {
            const cluster_byte_offset = cluster_byte_count * cluster_index;
            const slice_start = cluster_byte_offset;
            const slice_end = cluster_byte_offset + cluster_byte_count;
            const slice = file_content[slice_start..if (slice_end > file_content.len) file_content.len else slice_end];
            const lba = cache.clusterToSector(cluster);
            try cache.disk.writeSlice(u8, slice, lba, true);
        }

        return clusters[0];
    }

    const Size = struct {
        len: u16,
        size: u16,
    };

    fn translateToUnicode(name: []const u8, buffer: []u16) !Size {
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

        return .{ .len = @as(u16, @intCast(len)), .size = @as(u16, @intCast(size)) };
    }

    const BadChar = error{
        bad_value,
        last_character_space,
    };

    fn checkBadCharacters(string: []u16) !void {
        for (string) |wchar| {
            if (wchar < 0x20 or wchar == '*' or wchar == '?' or wchar == '<' or wchar == '>' or wchar == '|' or wchar == '"' or wchar == ':' or wchar == '/' or wchar == '\\') return BadChar.bad_value;
        }

        if (string[string.len - 1] == ' ') return BadChar.last_character_space;
    }

    fn isSkipCharacter(wchar: u16) bool {
        return wchar == '.' or wchar == ' ';
    }

    fn isReplaceCharacter(wchar: u16) bool {
        return wchar == '[' or wchar == ']' or wchar == ';' or wchar == ',' or wchar == '+' or wchar == '=';
    }

    const ShortNameInfo = packed struct(u8) {
        len: u5 = 0,
        lower: bool = true,
        upper: bool = true,
        valid: bool = true,
    };

    fn toShortNameCharacter(nls: *const NLS.Table, wchar: u16, char_buffer: []u8) !ShortNameInfo {
        var is_lower = true;
        var is_upper = true;
        var is_valid = true;

        if (isSkipCharacter(wchar)) @panic("short names must not contain skip characters");
        if (isReplaceCharacter(wchar)) @panic("short names must not contain replace characters");

        try nls.unicode_to_character(wchar, char_buffer);

        // TODO:
        const len = 1;
        if (len == 0) {
            @panic("nls: character length 0");
        } else if (len == 1) {
            const previous = char_buffer[0];

            if (previous >= 0x7f) @panic("nls: character value is too high");

            char_buffer[0] = nls.to_upper(previous);
            if (lib.isAlphabetic(char_buffer[0])) {
                if (char_buffer[0] == previous) {
                    is_lower = false;
                } else {
                    is_upper = false;
                }
            }
        } else @panic("nls: unexpected length");

        return ShortNameInfo{
            .len = @as(u5, @intCast(len)),
            .lower = is_lower,
            .upper = is_upper,
            .valid = is_valid,
        };
    }

    const ShortNameResult = extern struct {
        name: [short_name_len]u8,
        case: NameCase,
    };

    fn createShortName(cache: Cache, nls: *const NLS.Table, long_name: []u16, cluster: u32, short_name_result: *ShortNameResult, allocator: ?*lib.Allocator) !bool {
        var is_short_name = true;
        const end = lib.ptrAdd(u16, &long_name[0], long_name.len);
        var extension_start: ?*u16 = end;
        var size: usize = 0;

        while (true) {
            extension_start = lib.maybePtrSub(u16, extension_start, 1);
            if (@intFromPtr(extension_start) < @intFromPtr(&long_name[0])) break;

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
            const extension_start_index = @divExact(@intFromPtr(ext_start) - @intFromPtr(&long_name[0]), @sizeOf(u16));
            const index = blk: {
                const slice = long_name[0..extension_start_index];

                for (slice, 0..) |wchar, index| {
                    if (!isSkipCharacter(wchar)) break :blk index;
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

        while (long_name_index < size) : (long_name_index += 1) {
            const wchar = long_name[long_name_index];
            // TODO: chl
            // TODO: shortname_info
            base_info = try toShortNameCharacter(nls, wchar, &char_buffer);

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

        if (base_len == 0) @panic("fat32: base length is 0");

        var extension_len: usize = 0;
        var extension: [4]u8 = undefined;
        if (extension_start) |ext_start| {
            const extension_start_index = @divExact(@intFromPtr(ext_start) - @intFromPtr(&long_name[0]), @sizeOf(u16));
            const extension_slice = long_name[extension_start_index..];
            var extension_index: usize = 0;
            for (extension_slice, 0..) |extension_u16, extension_pointer_index| {
                extension_info = toShortNameCharacter(nls, extension_u16, &char_buffer) catch continue;

                if (extension_len + extension_info.len > 3) {
                    is_short_name = false;
                    break;
                }

                for (char_buffer[0..extension_info.len]) |ch| {
                    extension[extension_index] = ch;
                    extension_index += 1;
                    extension_len += 1;
                }

                if (extension_len >= 3) {
                    if (extension_pointer_index + extension_start_index + 1 != long_name.len) {
                        is_short_name = false;
                    }

                    break;
                }
            }
        }

        extension[extension_len] = 0;
        base[base_len] = 0;

        if (base[0] == 0xe5) base[0] = 0x05;

        short_name_result.* = ShortNameResult{
            .name = blk: {
                var name = [1]u8{' '} ** short_name_len;
                @memcpy(name[0..base_len], base[0..base_len]);
                @memcpy(name[max_base_len .. max_base_len + extension_len], extension[0..extension_len]);
                break :blk name;
            },
            .case = .{ .base = .upper, .extension = .upper },
        };

        if (is_short_name and base_info.valid and extension_info.valid) {
            if (try cache.exists(&short_name_result.name, cluster, allocator)) @panic("fat32: entry with such name already exists");
            const result = switch (cache.name_configuration.create) {
                .windows_95 => base_info.upper and extension_info.upper,
                .windows_nt => @panic("fat32: unsupported name configuration"),
            };
            return result;
        }

        @panic("fat32: cannot create shortname");
    }

    pub fn scan(cache: Cache, name: []const u8, cluster: u32, allocator: ?*lib.Allocator) !?*DirectoryEntry {
        var iterator = DirectoryEntryIterator(DirectoryEntry).init(cluster);

        while (try iterator.next(cache, allocator)) |entry| {
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

        pub fn isExtended(entry: GenericEntry) bool {
            return entry.long_name_entries.len != 0;
        }

        pub fn getSlots(entry: GenericEntry) usize {
            return entry.long_name_entries.len + 1;
        }
    };

    pub fn buildSlots(cache: Cache, entry_setup: EntrySetup, maybe_allocator: ?*lib.Allocator, copy_entry: ?*DirectoryEntry) !void {
        var long_name_array = [1]u16{0} ** (long_name_max_characters + 2);
        const size = try translateToUnicode(entry_setup.name, &long_name_array);
        const long_name = long_name_array[0..size.len];
        try checkBadCharacters(long_name);

        var short_name_result: ShortNameResult = undefined;
        const can_get_away_with_short_name = try cache.createShortName(&NLS.ascii.table, long_name, entry_setup.content_cluster, &short_name_result, maybe_allocator);
        // TODO: timestamp
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
                .first_cluster_high = @as(u16, @truncate(entry_setup.content_cluster >> 16)),
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
                .first_cluster_low = @as(u16, @truncate(entry_setup.content_cluster)),
                .file_size = entry_setup.size,
            },
        };

        if (!can_get_away_with_short_name) {
            const checksum = shortNameCheckSum(&short_name_result.name);

            const long_slot_count = @as(u5, @intCast(size.size / character_count_per_long_entry));
            entry.long_name_entries = blk: {
                const allocator = maybe_allocator orelse @panic("fat32: allocator not provided");
                const alloc_result = try allocator.allocateBytes(@as(usize, @intCast(@sizeOf(LongNameEntry))) * long_slot_count, @alignOf(LongNameEntry));
                break :blk @as([*]LongNameEntry, @ptrFromInt(alloc_result.address))[0..long_slot_count];
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

        const total_slots = entry.getSlots();
        var free_slots: usize = 0;
        var entry_iterator = DirectoryEntryIterator(DirectoryEntry).init(entry_setup.containing_cluster);
        var current_cluster: u32 = 0;

        while (try entry_iterator.next(cache, maybe_allocator)) |cluster_entry| {
            if (cluster_entry.isFree()) {
                if (free_slots == 0) current_cluster = @as(u32, @intCast(entry_iterator.cluster));
                free_slots += 1;

                if (free_slots == total_slots) {
                    const last_current_cluster = @as(u32, @intCast(entry_iterator.cluster));
                    assert(last_current_cluster == current_cluster);
                    const element_offset = @divExact(@intFromPtr(cluster_entry) - @intFromPtr(&entry_iterator.cluster_entries[0]), @sizeOf(DirectoryEntry));
                    const entry_start_index = element_offset - (free_slots - 1);

                    var entry_index = entry_start_index;
                    for (entry.long_name_entries) |*long_name_entry| {
                        entry_iterator.cluster_entries[entry_index] = @as(DirectoryEntry, @bitCast(long_name_entry.*));
                        entry_index += 1;
                    }

                    entry_iterator.cluster_entries[entry_index] = entry.normal_entry;

                    try cache.disk.writeSlice(DirectoryEntry, entry_iterator.cluster_entries, entry_iterator.getCurrentLBA(cache), false);

                    return;
                }
            } else {
                free_slots = 0;
            }
        }

        @panic("fat32: cannot build slots");
    }

    const EntrySetup = struct {
        name: []const u8,
        size: u32 = 0,
        content_cluster: u32,
        containing_cluster: u32,
        is_dir: bool,
    };

    pub fn addEntry(cache: Cache, entry_setup: EntrySetup, maybe_allocator: ?*lib.Allocator, copy_entry: ?*DirectoryEntry, miliseconds: u64) !void {
        _ = miliseconds;

        // TODO:
        if (entry_setup.name[entry_setup.name.len - 1] == '.') @panic("todo: unexpected trailing dot");

        try cache.buildSlots(entry_setup, maybe_allocator, copy_entry);
    }

    pub fn shortNameCheckSum(name: []const u8) u8 {
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

    pub fn allocateNewDirectory(cache: Cache, containing_cluster: u32, allocator: ?*lib.Allocator, copy_cache: ?FAT32.Cache) !u32 {
        var clusters = [1]u32{0};
        try cache.allocateClusters(&clusters, allocator);
        const cluster = clusters[0];
        const lba = cache.clusterToSector(cluster);
        const fat_directory_entries = try cache.disk.readTypedSectors(FAT32.DirectoryEntry.Sector, lba, allocator, .{});

        var copy_entry: ?*FAT32.DirectoryEntry = null;
        if (copy_cache) |cp_cache| {
            const entries = try cp_cache.disk.readTypedSectors(FAT32.DirectoryEntry.Sector, cp_cache.clusterToSector(cluster), allocator, .{});
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

        const date = .{
            .day = 0,
            .month = 0,
            .year = 0,
        };
        const time = .{
            .seconds_2_factor = 0,
            .minutes = 0,
            .hours = 0,
        };
        fat_directory_entries[0] = FAT32.DirectoryEntry{
            .name = dot_entry_name,
            .attributes = attributes,
            .case = .{},
            .creation_time_tenth = if (copy_entry) |ce| ce.creation_time_tenth else 0,
            .creation_time = if (copy_entry) |ce| ce.creation_time else time,
            .creation_date = if (copy_entry) |ce| ce.creation_date else date,
            .first_cluster_high = @as(u16, @truncate(cluster >> 16)),
            .first_cluster_low = @as(u16, @truncate(cluster)),
            .last_access_date = if (copy_entry) |ce| ce.last_access_date else date,
            .last_write_time = if (copy_entry) |ce| ce.last_write_time else time,
            .last_write_date = if (copy_entry) |ce| ce.last_write_date else date,
            .file_size = 0,
        };
        // Copy the values and only modify the necessary ones
        fat_directory_entries[1] = fat_directory_entries[0];
        fat_directory_entries[1].name = dot_dot_entry_name;
        // TODO: Fix this
        fat_directory_entries[1].setFirstCluster(if (containing_cluster == cache.getRootCluster()) 0 else containing_cluster);
        // if (copy_entry) |cp_entry| {
        //     const copy_cluster = cp_entry.get_first_cluster();
        //     const dot_entry_cluster = fat_directory_entries[0].get_first_cluster();
        //     const dot_dot_entry_cluster = fat_directory_entries[1].get_first_cluster();
        // }

        // TODO: zero initialize the unused part of the cluster
        try cache.disk.writeTypedSectors(FAT32.DirectoryEntry.Sector, fat_directory_entries, lba, false);

        return cluster;
    }

    pub inline fn clusterToSector(cache: Cache, cluster: u32) u64 {
        return (@as(u64, cluster) - cache.getRootCluster()) * cache.getClusterSectorCount() + cache.getDataLBA();
    }

    pub fn registerCluster(cache: Cache, cluster: u32, entry: Entry, allocator: ?*lib.Allocator) !void {
        const fat_lba = cache.getFATLBA();
        const fat_entry_count = cache.mbr.bpb.dos3_31.dos2_0.fat_count;
        const fat_entry_sector_count = cache.mbr.bpb.fat_sector_count_32;

        if (entry.isAllocating()) {
            cache.fs_info.last_allocated_cluster = cluster;
            cache.fs_info.free_cluster_count -= 1;
        }

        // Actually allocate FAT entry

        var fat_index: u8 = 0;

        const fat_entry_sector_index = cluster % FAT32.Entry.per_sector;

        const cluster_offset = cluster * @sizeOf(u32) / cache.disk.sector_size;
        while (fat_index < fat_entry_count) : (fat_index += 1) {
            const fat_entry_lba = fat_lba + (fat_index * fat_entry_sector_count) + cluster_offset;
            const fat_entry_sector = try cache.disk.readTypedSectors(FAT32.Entry.Sector, fat_entry_lba, allocator, .{});
            fat_entry_sector[fat_entry_sector_index] = entry;
            try cache.disk.writeTypedSectors(FAT32.Entry.Sector, fat_entry_sector, fat_entry_lba, false);
        }
    }

    pub fn allocateClusters(cache: Cache, clusters: []u32, maybe_allocator: ?*lib.Allocator) !void {
        var fat_entry_iterator = try FATEntryIterator.init(cache, maybe_allocator);
        var cluster_index: usize = 0;

        var previous_cluster: ?u32 = null;

        while (try fat_entry_iterator.next(cache, maybe_allocator)) |cluster| {
            const entry = &fat_entry_iterator.entries[cluster % Entry.per_sector];
            if (entry.isFree()) {
                if (previous_cluster) |pc| {
                    if (pc != cluster - 1) {
                        // log.debug("PC: 0x{x}. CC: 0x{x}", .{ pc, cluster });
                        @panic("allocateClusters: unreachable");
                    }
                }
                const should_return = cluster_index == clusters.len - 1;
                try cache.registerCluster(cluster, if (should_return) Entry.allocated_and_eof else Entry{
                    .next_cluster = @as(u28, @intCast(cluster + 1)),
                }, maybe_allocator);
                clusters[cluster_index] = cluster;
                cluster_index += 1;

                if (should_return) {
                    // const first_cluster = @intCast(u32, cluster - clusters.len + 1);
                    // log.debug("First cluster: 0x{x}. Last cluster: 0x{x}", .{ first_cluster, cluster });
                    // log.debug("Allocated cluster range: {}-{}. LBA range: 0x{x}-0x{x}", .{ first_cluster, cluster, cache.clusterToSector(first_cluster), cache.clusterToSector(cluster) });
                    return;
                }

                previous_cluster = cluster;
            } else if (cluster_index > 0) {
                @panic("cluster index unreachable");
            }
        }

        @panic("fat32: allocateClusters");
    }

    pub fn getDirectoryEntry(cache: Cache, absolute_path: []const u8, copy_cache: ?Cache) !EntryResult(DirectoryEntry) {
        const fat_lba = cache.partition_range.first_lba + cache.mbr.bpb.dos3_31.dos2_0.reserved_sector_count;
        const root_cluster = cache.mbr.bpb.root_directory_cluster_offset;
        const data_lba = fat_lba + (cache.mbr.bpb.fat_sector_count_32 * cache.mbr.bpb.dos3_31.dos2_0.fat_count);

        const root_cluster_sector = data_lba;
        var upper_cluster = root_cluster;
        var dir_tokenizer = lib.DirectoryTokenizer.init(absolute_path);
        var directories: usize = 0;

        const first_dir = dir_tokenizer.next() orelse @panic("fat32: there must be at least one directory in the path");
        assert(lib.equal(u8, first_dir, "/"));

        entry_loop: while (dir_tokenizer.next()) |entry_name| : (directories += 1) {
            const is_last = dir_tokenizer.is_last();

            const copy_entry: ?*FAT32.DirectoryEntry = blk: {
                if (copy_cache) |cc| {
                    const name = absolute_path[0..dir_tokenizer.index];
                    const entry_result = try cc.getDirectoryEntry(name, null);
                    break :blk entry_result.directory_entry;
                } else break :blk null;
            };
            _ = copy_entry;

            const normalized_name = packString(entry_name, .{
                .len = short_name_len,
                .fill_with = ' ',
                .upper = true,
            });

            while (true) : (upper_cluster += 1) {
                const cluster_sector_offset = root_cluster_sector + cache.getClusterSectorCount() * (upper_cluster - root_cluster);
                const directory_entries_in_cluster = try cache.disk.readTypedSectors(DirectoryEntry.Sector, cluster_sector_offset, cache.allocator, .{});

                var entry_index: usize = 0;
                while (entry_index < directory_entries_in_cluster.len) : ({
                    entry_index += 1;
                }) {
                    const directory_entry = &directory_entries_in_cluster[entry_index];
                    const is_empty = directory_entry.name[0] == 0;
                    const is_unused = directory_entry.name[0] == 0xe5;
                    const is_long_name = directory_entry.attributes.hasLongName();

                    // At this point all entries in the given directory have been checked, so it's safe to say the directory doesn't contain the wanted entry
                    if (is_empty) {
                        return GetError.not_found;
                    } else {
                        if (is_unused) {
                            @panic("fat32: unused entry found");
                        } else if (is_long_name) {
                            const long_name_entry = @as(*FAT32.LongNameEntry, @ptrCast(directory_entry));
                            const original_starting_index = entry_index;

                            if (long_name_entry.isLast()) {
                                entry_index += 1;
                                assert(entry_index < directory_entries_in_cluster.len);
                                const long_name_u16 = long_name_entry.getCharacters();
                                var arr: [long_name_u16.len]u8 = [1]u8{0} ** long_name_u16.len;
                                const long_name_u8 = blk: {
                                    for (long_name_u16, 0..) |u16_ch, index| {
                                        if (u16_ch == 0) {
                                            break :blk arr[0..index];
                                        } else if (u16_ch <= lib.maxInt(u8)) {
                                            arr[index] = @as(u8, @intCast(u16_ch));
                                        } else {
                                            @panic("fat32: u16 unreachable");
                                        }
                                    }

                                    @panic("long_name_u8 unreachable");
                                };

                                // TODO: compare long name entry
                                if (lib.equal(u8, long_name_u8, entry_name)) {
                                    const normal_entry = &directory_entries_in_cluster[entry_index];
                                    if (is_last) {
                                        return .{ .cluster = upper_cluster, .entry_starting_index = @as(u32, @intCast(original_starting_index)), .directory_entry = normal_entry };
                                    } else {
                                        upper_cluster = normal_entry.getFirstCluster();
                                        continue :entry_loop;
                                    }
                                }
                            } else {
                                @panic("fat32: not last entry");
                            }
                        } else {
                            if (lib.equal(u8, &directory_entry.name, &normalized_name)) {
                                if (is_last) {
                                    return .{ .cluster = upper_cluster, .entry_starting_index = @as(u32, @intCast(entry_index)), .directory_entry = directory_entry };
                                } else {
                                    upper_cluster = directory_entry.getFirstCluster();
                                    continue :entry_loop;
                                }
                            }
                        }
                    }
                }

                return GetError.not_found;
            }
        }

        @panic("fat32: unable to get directory entry");
    }

    pub inline fn getFATLBA(cache: Cache) u64 {
        const fat_lba = cache.partition_range.first_lba + cache.mbr.bpb.dos3_31.dos2_0.reserved_sector_count;
        return fat_lba;
    }

    pub inline fn getDataLBA(cache: Cache) u64 {
        const data_lba = cache.getFATLBA() + (cache.mbr.bpb.fat_sector_count_32 * cache.mbr.bpb.dos3_31.dos2_0.fat_count);
        return data_lba;
    }

    pub inline fn getRootCluster(cache: Cache) u32 {
        const root_cluster = cache.mbr.bpb.root_directory_cluster_offset;
        return root_cluster;
    }

    pub inline fn getClusterSectorCount(cache: Cache) u32 {
        return cache.mbr.bpb.dos3_31.dos2_0.cluster_sector_count;
    }
};

const PackStringOptions = packed struct(u64) {
    fill_with: u8,
    len: u8,
    upper: bool,
    reserved: u47 = 0,
};

pub inline fn packString(name: []const u8, comptime options: PackStringOptions) [options.len]u8 {
    var result = [1]u8{options.fill_with} ** options.len;
    if (name.len > 0) {
        if (options.upper) {
            _ = lib.upperString(&result, name);
        } else {
            @memcpy(&result, name);
        }
    }

    return result;
}

const character_count_per_long_entry = 13;

fn EntryResult(comptime EntryType: type) type {
    return extern struct {
        entry_starting_index: usize,
        directory_entry: *EntryType,
        cluster: u32,
    };
}

// Sadly we have to wrap shell commands into scripts because of shell redirection usages

const FATEntryIterator = struct {
    entries: []FAT32.Entry = &.{},
    cluster: u32,

    fn init(cache: Cache, allocator: ?*lib.Allocator) !FATEntryIterator {
        const cluster = cache.fs_info.last_allocated_cluster + 1;
        assert(cache.disk.sector_size == @sizeOf(FAT32.Entry.Sector));
        const lba_offset = cache.getFATLBA() + (cluster / FAT32.Entry.per_sector);

        return .{
            .entries = try cache.disk.readTypedSectors(FAT32.Entry.Sector, lba_offset, allocator, .{}),
            .cluster = cluster,
        };
    }

    fn next(iterator: *FATEntryIterator, cache: Cache, allocator: ?*lib.Allocator) !?u32 {
        var cluster_count: usize = starting_cluster;
        // TODO: replace with proper variable
        const max_clusters = 100000;
        if (cache.disk.sector_size != @sizeOf(FAT32.Entry.Sector)) @panic("Unexpected disk sector size");

        while (cluster_count < max_clusters) {
            if (cluster_count >= max_clusters) cluster_count = starting_cluster;

            if (iterator.cluster != 0 and iterator.cluster % iterator.entries.len == 0) {
                const lba_offset = cache.getFATLBA() + (iterator.cluster / FAT32.Entry.per_sector);
                iterator.entries = try cache.disk.readTypedSectors(FAT32.Entry.Sector, lba_offset, allocator, .{});
            }

            const result = iterator.cluster;
            iterator.cluster += 1;
            return result;
        }

        @panic("fat32: entry iterator unreachable");
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

        pub fn getCurrentLBA(iterator: *Iterator, cache: Cache) u64 {
            const cluster_lba = cache.clusterToSector(iterator.cluster);
            return cluster_lba;
        }

        pub fn next(iterator: *Iterator, cache: Cache, allocator: ?*lib.Allocator) !?*EntryType {
            if (iterator.cluster_fetched) iterator.cluster_it += 1;

            const cluster_sector_count = cache.getClusterSectorCount();
            const cluster_entry_count = @divExact(cluster_sector_count * cache.disk.sector_size, @sizeOf(EntryType));
            assert(iterator.cluster_it <= cluster_entry_count);
            if (iterator.cluster_it == cluster_entry_count) return null; // TODO: Should we early return like this?

            if (!iterator.cluster_fetched or iterator.cluster_it == cluster_entry_count) {
                if (iterator.cluster_it == cluster_entry_count) iterator.cluster += 1;

                const cluster_lba = cache.clusterToSector(iterator.cluster);
                iterator.cluster_entries = try cache.disk.readSlice(EntryType, cluster_entry_count, cluster_lba, allocator, .{});
                iterator.cluster_it = 0;
                iterator.cluster_fetched = true;
            }

            return &iterator.cluster_entries[iterator.cluster_it];
        }
    };
}
