const GPT = @This();

const lib = @import("lib");
const assert = lib.assert;
const kb = lib.kb;
const mb = lib.mb;
const gb = lib.gb;
const CRC32 = lib.CRC32;
const Disk = lib.Disk;
const Filesystem = lib.Filesystem;
const FAT32 = Filesystem.FAT32;
const log = lib.log.scoped(.GPT);
const MBR = lib.PartitionTable.MBR;
const GUID = lib.uefi.Guid;
const Allocator = lib.Allocator;

pub const default_max_partition_count = 128;
pub const min_block_size = lib.default_sector_size;
pub const max_block_size = 0x1000;

pub const Header = extern struct {
    signature: [8]u8 = "EFI PART".*,
    revision: [4]u8 = .{ 0, 0, 1, 0 },
    header_size: u32 = @sizeOf(Header),
    header_crc32: u32 = 0,
    reserved: u32 = 0,
    header_lba: u64,
    backup_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    disk_guid: GUID,
    partition_array_lba: u64,
    partition_entry_count: u32,
    partition_entry_size: u32 = @sizeOf(Partition),
    partition_array_crc32: u32,
    reserved1: [420]u8 = [1]u8{0} ** 420,

    pub fn updateCrc32(header: *Header) void {
        header.header_crc32 = 0;
        header.header_crc32 = CRC32.compute(lib.asBytes(header)[0..header.header_size]);
    }

    pub fn getPartititonCountInSector(header: *const Header, disk: *const Disk) u32 {
        return @divExact(disk.sector_size, header.partition_entry_size);
    }

    pub fn format(header: *const Header, comptime _: []const u8, _: lib.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try lib.format(writer, "GPT header:\n", .{});
        try lib.format(writer, "\tSignature: {s}\n", .{header.signature});
        try lib.format(writer, "\tRevision: {any}\n", .{header.revision});
        try lib.format(writer, "\tHeader size: {}\n", .{header.header_size});
        try lib.format(writer, "\tHeader CRC32: 0x{x}\n", .{header.header_crc32});
        try lib.format(writer, "\tHeader LBA: 0x{x}\n", .{header.header_lba});
        try lib.format(writer, "\tAlternate header LBA: 0x{x}\n", .{header.backup_lba});
        try lib.format(writer, "\tFirst usable LBA: 0x{x}\n", .{header.first_usable_lba});
        try lib.format(writer, "\tLast usable LBA: 0x{x}\n", .{header.last_usable_lba});
        try lib.format(writer, "\tDisk GUID: {}\n", .{header.disk_guid});
        try lib.format(writer, "\tPartition array LBA: 0x{x}\n", .{header.partition_array_lba});
        try lib.format(writer, "\tPartition entry count: {}\n", .{header.partition_entry_count});
        try lib.format(writer, "\tPartition entry size: {}\n", .{header.partition_entry_size});
        try lib.format(writer, "\tPartition array CRC32: 0x{x}\n", .{header.partition_array_crc32});
    }

    pub fn compare(header: *const Header, other: *align(1) const Header) void {
        log.debug("{}", .{header});
        log.debug("{}", .{other});

        if (!lib.equal(u8, &header.signature, &other.signature)) {
            log.debug("Signature mismatch: {s}, {s}", .{ header.signature, other.signature });
        }
        if (!lib.equal(u8, &header.revision, &other.revision)) {
            log.debug("Revision mismatch: {any}, {any}", .{ header.revision, other.revision });
        }
        if (header.header_size != other.header_size) {
            log.debug("Header size mismatch: {}, {}", .{ header.header_size, other.header_size });
        }
        if (header.header_crc32 != other.header_crc32) {
            log.debug("Header CRC32 mismatch: {}, {}", .{ header.header_crc32, other.header_crc32 });
        }
        if (header.header_lba != other.header_lba) {
            log.debug("Header LBA mismatch: {}, {}", .{ header.header_lba, other.header_lba });
        }
        if (header.backup_lba != other.backup_lba) {
            log.debug("Backup LBA mismatch: {}, {}", .{ header.backup_lba, other.backup_lba });
        }
        if (header.first_usable_lba != other.first_usable_lba) {
            log.debug("First usable LBA mismatch: {}, {}", .{ header.first_usable_lba, other.first_usable_lba });
        }
        if (header.last_usable_lba != other.last_usable_lba) {
            log.debug("Last usable LBA mismatch: {}, {}", .{ header.last_usable_lba, other.last_usable_lba });
        }
        if (!header.disk_guid.eql(other.disk_guid)) {
            log.debug("Disk GUID mismatch: {}, {}", .{ header.disk_guid, other.disk_guid });
        }
        if (header.partition_array_lba != other.partition_array_lba) {
            log.debug("Partition array LBA mismatch: {}, {}", .{ header.partition_array_lba, other.partition_array_lba });
        }
        if (header.partition_entry_count != other.partition_entry_count) {
            log.debug("Partition entry count mismatch: {}, {}", .{ header.partition_entry_count, other.partition_entry_count });
        }
        if (header.partition_entry_size != other.partition_entry_size) {
            log.debug("Partition entry size mismatch: {}, {}", .{ header.partition_entry_size, other.partition_entry_size });
        }
        if (header.partition_array_crc32 != other.partition_array_crc32) {
            log.debug("Partition array CRC32 mismatch: {}, {}", .{ header.partition_array_crc32, other.partition_array_crc32 });
        }
    }

    pub const Cache = extern struct {
        mbr: *MBR.Partition,
        header: *GPT.Header,
        disk: *Disk,
        gpt: *GPT.Partition,

        pub fn getFreePartitionSlot(cache: Cache) !*GPT.Partition {
            assert(cache.header.partition_entry_size == @sizeOf(GPT.Partition));
            // TODO: undo hack

            return cache.gpt;

            // for (cache.partition_entries[0..cache.header.partition_entry_count]) |*partition_entry| {
            //     if (partition_entry.first_lba == 0 and partition_entry.last_lba == 0) {
            //         return partition_entry;
            //     }
            // }

            //@panic("todo: get_free_partition_slot");
        }

        pub fn getPartitionIndex(cache: Cache, partition: *GPT.Partition, partition_entries: []GPT.Partition) u32 {
            assert(cache.header.partition_entry_size == @sizeOf(GPT.Partition));
            return @divExact(@as(u32, @intCast(@intFromPtr(partition) - @intFromPtr(partition_entries.ptr))), cache.header.partition_entry_size);
        }

        pub fn getPartitionSector(cache: Cache, partition: *GPT.Partition, partition_entries: []GPT.Partition) u32 {
            return getPartitionIndex(cache, partition, partition_entries) / cache.header.getPartititonCountInSector(cache.disk);
        }

        pub fn getPartitionEntries(cache: Cache, allocator: ?*lib.Allocator) ![]GPT.Partition {
            const partition_entries = try cache.disk.readSlice(GPT.Partition, cache.header.partition_entry_count, cache.header.partition_array_lba, allocator, .{});
            return partition_entries;
        }

        pub inline fn updatePartitionEntry(cache: Cache, partition: *GPT.Partition, new_value: GPT.Partition) !void {
            if (cache.disk.type != .memory) @panic("Disk is not memory");
            assert(cache.header.partition_entry_size == @sizeOf(GPT.Partition));
            const partition_entries = try cache.getPartitionEntries(null);
            const partition_entry_bytes = lib.sliceAsBytes(partition_entries);
            partition.* = new_value;
            cache.header.partition_array_crc32 = CRC32.compute(partition_entry_bytes);
            cache.header.updateCrc32();

            const backup_gpt_header = try cache.disk.readTypedSectors(GPT.Header, cache.header.backup_lba, null, .{});
            backup_gpt_header.partition_array_crc32 = cache.header.partition_array_crc32;
            backup_gpt_header.updateCrc32();

            const partition_entry_sector_offset = cache.getPartitionSector(partition, partition_entries);
            const partition_entry_byte_offset = partition_entry_sector_offset * cache.disk.sector_size;
            // Only commit to disk the modified sector
            const partition_entry_modified_sector_bytes = partition_entry_bytes[partition_entry_byte_offset .. partition_entry_byte_offset + cache.disk.sector_size];
            try cache.disk.writeSlice(u8, partition_entry_modified_sector_bytes, cache.header.partition_array_lba + partition_entry_sector_offset, false);
            // Force write because for memory disk we only hold a pointer to the main partition entry array
            try cache.disk.writeSlice(u8, partition_entry_modified_sector_bytes, backup_gpt_header.partition_array_lba + partition_entry_sector_offset, true);
            try cache.disk.writeTypedSectors(GPT.Header, cache.header, cache.header.header_lba, false);
            try cache.disk.writeTypedSectors(GPT.Header, backup_gpt_header, backup_gpt_header.header_lba, false);
        }

        pub fn addPartition(cache: Cache, comptime filesystem: lib.Filesystem.Type, partition_name: []const u16, lba_start: u64, lba_end: u64, gpt_partition: ?*const GPT.Partition) !GPT.Partition.Cache {
            // TODO: check if we are not overwriting a partition
            // TODO: check filesystem specific stuff
            const new_partition_entry = try cache.getFreePartitionSlot();
            try updatePartitionEntry(cache, new_partition_entry, GPT.Partition{
                .partition_type_guid = switch (filesystem) {
                    .fat32 => efi_guid,
                    else => @panic("unexpected filesystem"),
                },
                .unique_partition_guid = if (gpt_partition) |gpt_part| gpt_part.unique_partition_guid else getRandomGuid(),
                .first_lba = lba_start,
                .last_lba = lba_end,
                .attributes = .{},
                .partition_name = blk: {
                    var name = [1]u16{0} ** 36;
                    @memcpy(name[0..partition_name.len], partition_name);
                    break :blk name;
                },
            });

            return .{
                .gpt = cache,
                .partition = new_partition_entry,
            };
        }

        pub fn load(disk: *Disk, allocator: ?*Allocator) !GPT.Header.Cache {
            _ = allocator;
            _ = disk;
        }
    };

    comptime {
        assert(@sizeOf(Header) == lib.default_sector_size);
    }

    pub fn get(disk: *Disk) !*GPT.Header {
        return try disk.readTypedSectors(GPT.Header, 1);
    }

    pub fn getBackup(gpt_header: *GPT.Header, disk: *Disk) !*GPT.Header {
        return try disk.readTypedSectors(GPT.Header, gpt_header.backup_lba);
    }
};

var prng = lib.random.DefaultPrng.init(0);
pub fn getRandomGuid() GUID {
    const random_array = blk: {
        var arr: [16]u8 = undefined;
        const random = prng.random();
        random.bytes(&arr);
        break :blk arr;
    };
    var guid = GUID{
        .time_low = (@as(u32, random_array[0]) << 24) | (@as(u32, random_array[1]) << 16) | (@as(u32, random_array[2]) << 8) | random_array[3],
        .time_mid = (@as(u16, random_array[4]) << 8) | random_array[5],
        .time_high_and_version = (@as(u16, random_array[6]) << 8) | random_array[7],
        .clock_seq_high_and_reserved = random_array[8],
        .clock_seq_low = random_array[9],
        .node = .{ random_array[10], random_array[11], random_array[12], random_array[13], random_array[14], random_array[15] },
    };

    guid.clock_seq_high_and_reserved = (2 << 6) | (guid.clock_seq_high_and_reserved >> 2);
    guid.time_high_and_version = (4 << 12) | (guid.time_high_and_version >> 4);

    return guid;
}

pub const efi_system_partition_guid = GUID{ .time_low = 0xC12A7328, .time_mid = 0xF81F, .time_hi_and_version = 0x11D2, .clock_seq_hi_and_reserved = 0xBA, .clock_seq_low = 0x4B, .node = [_]u8{ 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B } };
pub const microsoft_basic_data_partition_guid = GUID{ .time_low = 0xEBD0A0A2, .time_mid = 0xB9E5, .time_hi_and_version = 0x4433, .clock_seq_hi_and_reserved = 0x87, .clock_seq_low = 0xC0, .node = [_]u8{ 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7 } };

pub const Partition = extern struct {
    partition_type_guid: GUID,
    unique_partition_guid: GUID,
    first_lba: u64,
    last_lba: u64,
    attributes: Attributes,
    partition_name: [36]u16,

    pub const per_sector = @divExact(lib.default_sector_size, @sizeOf(Partition));

    pub const Cache = extern struct {
        gpt: GPT.Header.Cache,
        partition: *GPT.Partition,

        pub fn fromPartitionIndex(disk: *Disk, partition_index: usize, allocator: ?*lib.Allocator) !GPT.Partition.Cache {
            const mbr_lba = MBR.default_lba;
            const mbr = try disk.readTypedSectors(MBR.Partition, mbr_lba, allocator, .{});
            const primary_gpt_header_lba = mbr_lba + 1;
            const gpt_header = try disk.readTypedSectors(GPT.Header, primary_gpt_header_lba, allocator, .{});
            if (gpt_header.partition_entry_count == 0) @panic("No GPT partition entries");
            assert(gpt_header.partition_entry_size == @sizeOf(GPT.Partition));
            // TODO: undo hack
            if (partition_index < gpt_header.partition_entry_count) {
                if (partition_index != 0) @panic("Unsupported partition index");
                const partition_entries_first_sector = try disk.readSlice(GPT.Partition, GPT.Partition.per_sector, gpt_header.partition_array_lba, allocator, .{});
                const partition_entry = &partition_entries_first_sector[0];

                return .{
                    .gpt = .{
                        .mbr = mbr,
                        .header = gpt_header,
                        .disk = disk,
                        .gpt = partition_entry,
                    },
                    .partition = partition_entry,
                };
            }

            @panic("todo: fromPartitionIndex");
        }
    };

    pub const Attributes = packed struct(u64) {
        required_partition: bool = false,
        no_block_io_protocol: bool = false,
        legacy_bios_bootable: bool = false,
        reserved: u45 = 0,
        guid_reserved: u16 = 0,
    };

    pub fn compare(partition: *const Partition, other: *align(1) const Partition) void {
        log.debug("{}", .{partition});
        if (partition.first_lba != other.first_lba) {
            log.debug("First LBA mismatch: 0x{x}, 0x{x}", .{ partition.first_lba, other.first_lba });
        }
        if (partition.last_lba != other.last_lba) {
            log.debug("Last LBA mismatch: 0x{x}, 0x{x}", .{ partition.last_lba, other.last_lba });
        }
        for (partition.partition_name, 0..) |partition_char, char_index| {
            const other_char = other.partition_name[char_index];
            if (partition_char != other_char) {
                log.debug("Char is different: {u}(0x{x}), {u}(0x{x})", .{ partition_char, partition_char, other_char, other_char });
            }
        }
    }

    pub fn format(partition: *const Partition, comptime _: []const u8, _: lib.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try lib.format(writer, "GPT partition:\n", .{});
        try lib.format(writer, "\tPartition type GUID: {}\n", .{partition.partition_type_guid});
        try lib.format(writer, "\tUnique partition GUID: {}\n", .{partition.unique_partition_guid});
        try lib.format(writer, "\tFirst LBA: 0x{x}\n", .{partition.first_lba});
        try lib.format(writer, "\tLast LBA: 0x{x}\n", .{partition.last_lba});
        try lib.format(writer, "\tAttributes: {}\n", .{partition.attributes});
        try lib.format(writer, "\tPartition name: {}\n", .{lib.std.unicode.fmtUtf16le(&partition.partition_name)});
    }
};

pub fn create(disk: *Disk, copy_gpt_header: ?*const Header) !GPT.Header.Cache {
    if (disk.type != .memory) @panic("gpt: creation is only supported for memory disks");
    // 1. Create MBR fake partition
    const mbr_lba = MBR.default_lba;
    const mbr = try disk.readTypedSectors(MBR.Partition, mbr_lba, null, .{});
    const first_lba = mbr_lba + 1;
    const primary_header_lba = first_lba;
    mbr.partitions[0] = MBR.LegacyPartition{
        .boot_indicator = 0,
        .starting_chs = lib.default_sector_size,
        .os_type = 0xee,
        .ending_chs = 0xff_ff_ff,
        .first_lba = first_lba,
        .size_in_lba = @as(u32, @intCast(@divExact(disk.disk_size, disk.sector_size) - 1)),
    };
    mbr.signature = .{ 0x55, 0xaa };
    try disk.writeTypedSectors(MBR.Partition, mbr, mbr_lba, false);

    // 2. Write GPT header
    const partition_count = default_max_partition_count;
    const partition_array_sector_count = @divExact(@sizeOf(Partition) * partition_count, disk.sector_size);
    // TODO: properly compute header LBA
    const gpt_header = try disk.readTypedSectors(GPT.Header, first_lba, null, .{});
    const secondary_header_lba = mbr.partitions[0].size_in_lba;
    const partition_array_lba_start = first_lba + 1;
    const partition_entries = try disk.readSlice(GPT.Partition, partition_count, partition_array_lba_start, null, .{});
    gpt_header.* = GPT.Header{
        .signature = "EFI PART".*,
        .revision = .{ 0, 0, 1, 0 },
        .header_size = @offsetOf(GPT.Header, "reserved1"),
        .header_crc32 = 0, // TODO
        .header_lba = primary_header_lba,
        .backup_lba = secondary_header_lba,
        .first_usable_lba = partition_array_lba_start + partition_array_sector_count,
        .last_usable_lba = secondary_header_lba - primary_header_lba - partition_array_sector_count,
        .disk_guid = if (copy_gpt_header) |gpth| gpth.disk_guid else getRandomGuid(),
        .partition_array_lba = partition_array_lba_start,
        .partition_entry_count = partition_count,
        .partition_array_crc32 = CRC32.compute(lib.sliceAsBytes(partition_entries)),
    };

    gpt_header.updateCrc32();
    try disk.writeTypedSectors(GPT.Header, gpt_header, primary_header_lba, false);

    var backup_gpt_header = gpt_header.*;
    backup_gpt_header.partition_array_lba = secondary_header_lba - primary_header_lba - partition_array_sector_count + 1;
    backup_gpt_header.header_lba = gpt_header.backup_lba;
    backup_gpt_header.backup_lba = gpt_header.header_lba;
    backup_gpt_header.updateCrc32();
    try disk.writeTypedSectors(GPT.Header, &backup_gpt_header, secondary_header_lba, true);

    return .{
        .mbr = mbr,
        .header = gpt_header,
        .disk = disk,
        .gpt = &partition_entries[0],
    };
}

const efi_guid = GUID{
    .time_low = 0xC12A7328,
    .time_mid = 0xF81F,
    .time_high_and_version = 0x11D2,
    .clock_seq_high_and_reserved = 0xBA,
    .clock_seq_low = 0x4B,
    //00A0C93EC93B
    .node = .{ 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b },
};

const limine_disk_guid = GUID{
    .time_low = 0xD2CB8A76,
    .time_mid = 0xACB3,
    .time_high_and_version = 0x4D4D,
    .clock_seq_high_and_reserved = 0x93,
    .clock_seq_low = 0x55,
    .node = .{ 0xAC, 0xAE, 0xA4, 0x6B, 0x46, 0x92 },
};

const limine_unique_partition_guid = GUID{
    .time_low = 0x26D6E02E,
    .time_mid = 0xEED8,
    .time_high_and_version = 0x4802,
    .clock_seq_high_and_reserved = 0xba,
    .clock_seq_low = 0xa2,
    .node = .{ 0xE5, 0xAA, 0x43, 0x7F, 0xC2, 0xC5 },
};

const FilesystemCacheTypes = blk: {
    var types: [Filesystem.Type.count]type = undefined;
    types[@intFromEnum(Filesystem.Type.rise)] = void;
    types[@intFromEnum(Filesystem.Type.ext2)] = void;
    types[@intFromEnum(Filesystem.Type.fat32)] = FAT32.Cache;

    break :blk types;
};

test "gpt size" {
    comptime {
        assert(@sizeOf(Header) == 0x200);
    }
}
