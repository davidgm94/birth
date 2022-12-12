const GPT = @This();

const common = @import("../../common.zig");
const assert = common.assert;
const kb = common.kb;
const mb = common.mb;
const gb = common.gb;
const CRC32 = common.CRC32;
const Disk = common.Disk;
const FAT32 = common.Filesystem.FAT32;
const log = common.log.scoped(.GPT);
const MBR = common.PartitionTable.MBR;
const GUID = common.std.os.uefi.Guid;

pub const reserved_partition_size = 1 * common.mb;
pub const max_partition_count = 128;
pub const partition_array_size = 16 * common.kb;
pub const min_block_size = 0x200;
pub const max_block_size = 0x1000;
pub const partition_array_lba_start = 2;
pub const master_boot_record_lba = 0;
pub const header_lba = master_boot_record_lba + 1;

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
    partition_entry_count: u32 = max_partition_count,
    partition_entry_size: u32 = @sizeOf(Partition),
    partition_array_crc32: u32,
    reserved1: [420]u8 = [1]u8{0} ** 420,

    pub fn update_crc32(header: *Header, disk: *Disk.Descriptor) !void {
        header.partition_array_crc32 = CRC32.compute(try disk.callbacks.read(disk, get_partition_array_sector_count(disk), partition_array_lba_start));
        header.header_crc32 = 0;
        header.header_crc32 = CRC32.compute(common.as_bytes(header)[0..header.header_size]);
    }

    pub fn get_partition(header: *const Header, disk: *Disk.Descriptor, partition_index: usize) !*GPT.Partition {
        const partition_entry_size = header.partition_entry_size;
        assert(disk.sector_size >= partition_entry_size);
        assert(disk.sector_size % partition_entry_size == 0);

        if (partition_index < header.partition_entry_count) {
            const partition_entry_array_lba = header.partition_array_lba;
            const partition_entry_per_sector_count = @divExact(disk.sector_size, partition_entry_size);
            const partition_entry_lba = (partition_index / partition_entry_per_sector_count) + partition_entry_array_lba;
            const partition_offset_from_lba = partition_index % partition_entry_per_sector_count;
            const partition_entry_sector = try disk.callbacks.read(disk, 1, partition_entry_lba);
            const partition_entry = @ptrCast(*GPT.Partition, @alignCast(@alignOf(GPT.Partition), partition_entry_sector[partition_offset_from_lba..]));
            return partition_entry;
        } else {
            return GetPartitionError.invalid_index;
        }
    }

    pub fn format(header: *const Header, comptime _: []const u8, _: common.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try common.internal_format(writer, "GPT header:\n", .{});
        try common.internal_format(writer, "\tSignature: {s}\n", .{header.signature});
        try common.internal_format(writer, "\tRevision: {any}\n", .{header.revision});
        try common.internal_format(writer, "\tHeader size: {}\n", .{header.header_size});
        try common.internal_format(writer, "\tHeader CRC32: 0x{x}\n", .{header.header_crc32});
        try common.internal_format(writer, "\tHeader LBA: 0x{x}\n", .{header.header_lba});
        try common.internal_format(writer, "\tAlternate header LBA: 0x{x}\n", .{header.backup_lba});
        try common.internal_format(writer, "\tFirst usable LBA: 0x{x}\n", .{header.first_usable_lba});
        try common.internal_format(writer, "\tLast usable LBA: 0x{x}\n", .{header.last_usable_lba});
        try common.internal_format(writer, "\tDisk GUID: {}\n", .{header.disk_guid});
        try common.internal_format(writer, "\tPartition array LBA: 0x{x}\n", .{header.partition_array_lba});
        try common.internal_format(writer, "\tPartition entry count: {}\n", .{header.partition_entry_count});
        try common.internal_format(writer, "\tPartition entry size: {}\n", .{header.partition_entry_size});
        try common.internal_format(writer, "\tPartition array CRC32: 0x{x}\n", .{header.partition_array_crc32});
    }

    pub fn compare(header: *const Header, other: *align(1) const Header) void {
        log.debug("{}", .{header});
        log.debug("{}", .{other});
        if (!common.equal(u8, &header.signature, &other.signature)) {
            log.debug("Signature mismatch: {s}, {s}", .{ header.signature, other.signature });
        }
        if (!common.equal(u8, &header.revision, &other.revision)) {
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

    comptime {
        assert(@sizeOf(Header) == 0x200);
    }
};

var prng = common.std.rand.DefaultPrng.init(0);
pub fn get_random_guid() GUID {
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
        for (partition.partition_name) |partition_char, char_index| {
            const other_char = other.partition_name[char_index];
            if (partition_char != other_char) {
                log.debug("Char is different: {u}(0x{x}), {u}(0x{x})", .{ partition_char, partition_char, other_char, other_char });
            }
        }
    }

    pub fn format(partition: *const Partition, comptime _: []const u8, _: common.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try common.internal_format(writer, "GPT partition:\n", .{});
        try common.internal_format(writer, "\tPartition type GUID: {}\n", .{partition.partition_type_guid});
        try common.internal_format(writer, "\tUnique partition GUID: {}\n", .{partition.unique_partition_guid});
        try common.internal_format(writer, "\tFirst LBA: 0x{x}\n", .{partition.first_lba});
        try common.internal_format(writer, "\tLast LBA: 0x{x}\n", .{partition.last_lba});
        try common.internal_format(writer, "\tAttributes: {}\n", .{partition.attributes});
        try common.internal_format(writer, "\tPartition name: {}\n", .{common.std.unicode.fmtUtf16le(&partition.partition_name)});
    }
};

pub fn create(disk: *Disk.Descriptor, write_options: Disk.Descriptor.WriteOptions) !*GPT.Header {
    // 1. Create MBR fake partition
    const mbr = try disk.read_typed_sectors(MBR.Struct, master_boot_record_lba);
    mbr.partitions[0] = MBR.Partition{
        .boot_indicator = 0,
        .starting_chs = 0x200,
        .os_type = 0xee,
        .ending_chs = 0xff_ff_ff,
        .first_lba = master_boot_record_lba + 1,
        .size_in_lba = @intCast(u32, @divExact(disk.disk_size, disk.sector_size) - 1),
    };
    mbr.signature = .{ 0x55, 0xaa };
    try disk.write_typed_sectors(MBR.Struct, mbr, master_boot_record_lba, write_options);

    // 2. Write GPT header
    const partition_array_sector_count = get_partition_array_sector_count(disk);
    const gpt_header = try get_header(disk);
    const primary_header_lba = GPT.header_lba;
    const secondary_header_lba = mbr.partitions[0].size_in_lba;
    gpt_header.* = GPT.Header{
        .signature = "EFI PART".*,
        .revision = .{ 0, 0, 1, 0 },
        .header_size = @offsetOf(GPT.Header, "reserved1"),
        .header_crc32 = 0, // TODO
        .header_lba = primary_header_lba,
        .backup_lba = secondary_header_lba,
        .first_usable_lba = partition_array_lba_start + partition_array_sector_count,
        .last_usable_lba = secondary_header_lba - header_lba - partition_array_sector_count,
        .disk_guid = limine_disk_guid,
        .partition_array_lba = partition_array_lba_start,
        .partition_array_crc32 = 0,
    };
    try gpt_header.update_crc32(disk);
    try disk.write_typed_sectors(GPT.Header, gpt_header, primary_header_lba, write_options);

    const backup_gpt_header = try disk.read_typed_sectors(GPT.Header, secondary_header_lba);
    backup_gpt_header.* = gpt_header.*;
    backup_gpt_header.partition_array_lba = secondary_header_lba - header_lba - partition_array_sector_count + 1;
    backup_gpt_header.header_lba = gpt_header.backup_lba;
    backup_gpt_header.backup_lba = gpt_header.header_lba;
    try backup_gpt_header.update_crc32(disk);
    try disk.write_typed_sectors(GPT.Header, backup_gpt_header, secondary_header_lba, write_options);

    return gpt_header;
}

pub fn get_partition_array_sector_count(disk: *Disk.Descriptor) u64 {
    const partition_array_sector_count = @divExact(@sizeOf(Partition) * max_partition_count, disk.sector_size);
    return partition_array_sector_count;
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

const limine_date = FAT32.Date.new(9, 12, 2022);
const limine_time = FAT32.Time.new(28, 20, 18);

pub fn add_partition(disk: *Disk.Descriptor, partition_name: []const u16, filesystem: common.Filesystem.Type, lba_start: u64, lba_end: u64, write_options: Disk.Descriptor.WriteOptions) !*GPT.Partition {
    // TODO: check if we are not overwriting a partition
    const gpt_header = try get_header(disk);
    const gpt_partition_table_lba = gpt_header.partition_array_lba;
    const gpt_first_partition_bytes = try disk.callbacks.read(disk, 1, gpt_partition_table_lba);
    const gpt_first_partition = @ptrCast(*GPT.Partition, @alignCast(@alignOf(GPT.Partition), gpt_first_partition_bytes.ptr));
    assert(gpt_first_partition.first_lba == 0 and gpt_first_partition.last_lba == 0);
    assert(gpt_header.first_usable_lba <= lba_start);
    assert(gpt_header.last_usable_lba >= lba_end);
    assert(partition_name.len <= gpt_first_partition.partition_name.len);
    gpt_first_partition.* = GPT.Partition{
        .partition_type_guid = efi_guid,
        .unique_partition_guid = limine_unique_partition_guid,
        .first_lba = lba_start,
        .last_lba = lba_end,
        .attributes = .{},
        .partition_name = common.zeroes([36]u16),
    };
    common.copy(u16, &gpt_first_partition.partition_name, partition_name);
    try gpt_header.update_crc32(disk);
    try disk.write_typed_sectors(GPT.Header, gpt_header, header_lba, write_options);
    try disk.callbacks.write(disk, gpt_first_partition_bytes, gpt_partition_table_lba, write_options);
    const backup_gpt_header = try disk.read_typed_sectors(GPT.Header, gpt_header.backup_lba);
    const backup_partition_array_lba = backup_gpt_header.partition_array_lba;
    try disk.callbacks.write(disk, gpt_first_partition_bytes, backup_partition_array_lba, .{});
    // We have to write to memory here mandatorily
    backup_gpt_header.* = gpt_header.*;
    backup_gpt_header.backup_lba = gpt_header.header_lba;
    backup_gpt_header.header_lba = gpt_header.backup_lba;
    backup_gpt_header.partition_array_lba = backup_partition_array_lba;
    try backup_gpt_header.update_crc32(disk);
    try disk.write_typed_sectors(GPT.Header, backup_gpt_header, gpt_header.backup_lba, write_options);
    // TODO: check filesystem specific stuff
    _ = filesystem;

    return gpt_first_partition;
}

// https://support.microsoft.com/en-us/topic/default-cluster-size-for-ntfs-fat-and-exfat-9772e6f1-e31a-00d7-e18f-73169155af95
// Last consulted: 28-11-22
pub fn get_cluster_size(fat_partition_size: u64) u64 {
    log.debug("fat partition size: 0x{x}", .{fat_partition_size});
    return if (fat_partition_size < 32 * mb)
        unreachable
    else if (fat_partition_size < 64 * mb)
        0x200
    else if (fat_partition_size < 128 * mb)
        1 * kb
    else if (fat_partition_size < 256 * mb)
        2 * kb
    else if (fat_partition_size < 8 * gb)
        4 * kb
    else if (fat_partition_size < 16 * gb)
        8 * kb
    else if (fat_partition_size < 32 * gb)
        16 * kb
    else
        unreachable;
}

pub const Barebones = struct {
    raw_bytes: []const u8,
    fat_partition_mbr: *align(1) const MBR.Struct,
    fs_info: *align(1) const FAT32.FSInfo,
    fat_entries: []align(1) const FAT32.Entry,
    root_fat_directory_entries: []align(1) const FAT32.DirectoryEntry,
};

fn cdiv(a: u32, b: u32) u32 {
    return (a + b - 1) / b;
}
const min_cluster_32 = 65525;
const max_cluster_32 = 268435446;

pub fn format(disk: *Disk.Descriptor, partition_index: usize, filesystem: common.Filesystem.Type, write_options: Disk.Descriptor.WriteOptions) !void {
    assert(filesystem == .fat32);

    const gpt_header = try get_header(disk);

    const gpt_partition = try gpt_header.get_partition(disk, partition_index);

    const partition_lba_start = gpt_partition.first_lba;
    const partition_lba_end = gpt_partition.last_lba;

    const fat_partition_mbr = try disk.read_typed_sectors(MBR.Struct, partition_lba_start);

    const sectors_per_track = 32;
    const total_sector_count_32 = @intCast(u32, common.align_backward(partition_lba_end - partition_lba_start, sectors_per_track));
    const fat_count = FAT32.count;

    var cluster_size: u8 = 1;
    const max_cluster_size = 128;
    var fat_data_sector_count: u32 = undefined;
    var fat_length_32: u32 = undefined;
    var cluster_count_32: u32 = undefined;
    while (true) {
        assert(cluster_size > 0);
        fat_data_sector_count = total_sector_count_32 - common.align_forward(u32, FAT32.reserved_sector_count, cluster_size);
        cluster_count_32 = (fat_data_sector_count * disk.sector_size + fat_count * 8) / (cluster_size * disk.sector_size + fat_count * 4);
        fat_length_32 = common.align_forward(u32, cdiv((cluster_count_32 + 2) * 4, disk.sector_size), cluster_size);
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
        unreachable;
    }

    var root_directory_entries: u64 = 0;
    _ = root_directory_entries;

    log.debug("Cluster size: {}. FAT data sector count: {}. FAT sector count: {}", .{ cluster_size, fat_data_sector_count, fat_length_32 });
    const reserved_sector_count = common.align_forward(u16, FAT32.reserved_sector_count, cluster_size);

    fat_partition_mbr.* = MBR.Struct{
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
                .hidden_sector_count = @intCast(u32, partition_lba_start),
                .total_sector_count_32 = total_sector_count_32,
            },
            .fat_sector_count_32 = fat_length_32,
            .drive_description = 0,
            .version = .{ 0, 0 },
            .root_directory_cluster_offset = FAT32.starting_cluster,
            .fs_info_sector = FAT32.fs_info_sector,
            .backup_boot_record_sector = FAT32.backup_boot_record_sector,
            .drive_number = 0x80,
            .extended_boot_signature = 0x29,
            .serial_number = 0xc6da2516,
            .volume_label = "NO NAME    ".*,
            .filesystem_type = "FAT32   ".*,
        },
        .code = [_]u8{
            0xe, 0x1f, 0xbe, 0x77, 0x7c, 0xac, 0x22, 0xc0, 0x74, 0xb, 0x56, 0xb4, 0xe, 0xbb, 0x7, 0x0, 0xcd, 0x10, 0x5e, 0xeb, 0xf0, 0x32, 0xe4, 0xcd, 0x16, 0xcd, 0x19, 0xeb, 0xfe, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x61, 0x20, 0x62, 0x6f, 0x6f, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x64, 0x69, 0x73, 0x6b, 0x2e, 0x20, 0x20, 0x50, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x20, 0x69, 0x6e, 0x73, 0x65, 0x72, 0x74, 0x20, 0x61, 0x20, 0x62, 0x6f, 0x6f, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x66, 0x6c, 0x6f, 0x70, 0x70, 0x79, 0x20, 0x61, 0x6e, 0x64, 0xd, 0xa, 0x70, 0x72, 0x65, 0x73, 0x73, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x74, 0x6f, 0x20, 0x74, 0x72, 0x79, 0x20, 0x61, 0x67, 0x61, 0x69, 0x6e, 0x20, 0x2e, 0x2e, 0x2e, 0x20, 0xd, 0xa,
        } ++ [1]u8{0} ** 227,
        // This should be zero
        .partitions = common.zeroes([4]MBR.Partition),
    };

    try disk.write_typed_sectors(MBR.Struct, fat_partition_mbr, partition_array_lba_start, write_options);

    const backup_boot_record_sector = partition_lba_start + fat_partition_mbr.bpb.backup_boot_record_sector;
    const backup_boot_record = try disk.read_typed_sectors(MBR.Struct, backup_boot_record_sector);
    backup_boot_record.* = fat_partition_mbr.*;
    try disk.write_typed_sectors(MBR.Struct, backup_boot_record, backup_boot_record_sector, write_options);

    const fs_info_lba = partition_lba_start + fat_partition_mbr.bpb.fs_info_sector;
    const fs_info = try disk.read_typed_sectors(FAT32.FSInfo, fs_info_lba);
    fs_info.* = .{
        .lead_signature = 0x41615252,
        .signature = 0x61417272,
        .free_cluster_count = fat_partition_mbr.bpb.dos3_31.total_sector_count_32 - 2017, // TODO: compute,
        .last_allocated_cluster = fat_partition_mbr.bpb.root_directory_cluster_offset,
        .trail_signature = 0xaa550000,
    };
    try disk.write_typed_sectors(FAT32.FSInfo, fs_info, fs_info_lba, write_options);

    const backup_fs_info_lba = backup_boot_record_sector + backup_boot_record.bpb.fs_info_sector;
    const backup_fs_info = try disk.read_typed_sectors(FAT32.FSInfo, backup_fs_info_lba);
    backup_fs_info.* = fs_info.*;
    try disk.write_typed_sectors(FAT32.FSInfo, backup_fs_info, backup_fs_info_lba, write_options);

    try write_fat_entry_slow(disk, fat_partition_mbr, partition_lba_start, FAT32.Entry.reserved_and_should_not_be_used_eof, 0, write_options);
    try write_fat_entry_slow(disk, fat_partition_mbr, partition_lba_start, FAT32.Entry.allocated_and_eof, 1, write_options); // reserved | media_type
    try write_fat_entry_slow(disk, fat_partition_mbr, partition_lba_start, FAT32.Entry.reserved_and_should_not_be_used_eof, 2, write_options);
}

fn write_fat_entry_slow(disk: *Disk.Descriptor, fat_partition_mbr: *MBR.Struct, partition_lba_start: u64, fat_entry: FAT32.Entry, fat_entry_index: usize, write_options: Disk.Descriptor.WriteOptions) !void {
    const fat_entries_lba = partition_lba_start + fat_partition_mbr.bpb.dos3_31.dos2_0.reserved_sector_count;
    const fat_entry_count = fat_partition_mbr.bpb.dos3_31.dos2_0.fat_count;
    const fat_entry_sector_count = fat_partition_mbr.bpb.fat_sector_count_32;
    var fat_index: u8 = 0;

    while (fat_index < fat_entry_count) : (fat_index += 1) {
        const fat_entry_lba = fat_entries_lba + (fat_index * fat_entry_sector_count) + (fat_entry_index * @sizeOf(u32) / disk.sector_size);
        const fat_entry_sector = try disk.read_typed_sectors(FATEntrySector, fat_entry_lba);
        const fat_entry_sector_index = fat_entry_index % disk.sector_size;
        fat_entry_sector[fat_entry_sector_index] = fat_entry;
        try disk.write_typed_sectors(FATEntrySector, fat_entry_sector, fat_entry_lba, write_options);
    }
}

fn allocate_fat_entry(disk: *Disk.Descriptor, fat_partition_mbr: *MBR.Struct, fs_info: *FAT32.FSInfo, partition_lba_start: u64, write_options: Disk.Descriptor.WriteOptions) !u32 {
    const cluster = fs_info.allocate_clusters(1);
    try write_fat_entry_slow(disk, fat_partition_mbr, partition_lba_start, FAT32.Entry.allocated_and_eof, cluster, write_options);
    return cluster;
}

const FATEntrySector = [@divExact(0x200, @sizeOf(FAT32.Entry))]FAT32.Entry;
const FATDirectoryEntrySector = [@divExact(0x200, @sizeOf(FAT32.DirectoryEntry))]FAT32.DirectoryEntry;

const GetPartitionError = error{
    invalid_index,
};

const dot_entry_name: [11]u8 = ".".* ++ ([1]u8{' '} ** 10);
const dot_dot_entry_name: [11]u8 = "..".* ++ ([1]u8{' '} ** 9);

fn insert_directory_entry_slow(disk: *Disk.Descriptor, desired_entry: FAT32.DirectoryEntry, insert: struct {
    cluster: u32,
    root_cluster: u32,
    cluster_sector_count: u16,
    root_cluster_sector: u64,
}) !void {
    const cluster_dir_lba = (insert.cluster - insert.root_cluster) * insert.cluster_sector_count + insert.root_cluster_sector;
    assert(insert.cluster_sector_count == 1);
    const fat_directory_entries = try disk.read_typed_sectors(FATDirectoryEntrySector, cluster_dir_lba);

    for (fat_directory_entries) |*entry, entry_index| {
        //log.debug("Entry: {}", .{entry});
        if (entry.is_free()) {
            log.debug("Inserting entry {s} in cluster {}. Cluster dir LBA: 0x{x}. Entry index: {}", .{ desired_entry.name, insert.cluster, cluster_dir_lba, entry_index });
            entry.* = desired_entry;
            return;
        }
    }

    unreachable;
}

pub fn mkdir(disk: *Disk.Descriptor, partition_index: usize, absolute_path: []const u8, write_options: Disk.Descriptor.WriteOptions, barebones: Barebones) !void {
    //log.debug("Barebones partition mbr: {}", .{barebones.fat_partition_mbr});
    const gpt_header = try get_header(disk);
    const partition_entry = try gpt_header.get_partition(disk, partition_index);
    const partition_start_lba = partition_entry.first_lba;
    //const partition_end_lba = partition_entry.last_lba;

    const partition_mbr = try disk.read_typed_sectors(MBR.Struct, partition_start_lba);
    const fs_info_sector = partition_start_lba + partition_mbr.bpb.fs_info_sector;
    const fs_info = try disk.read_typed_sectors(FAT32.FSInfo, fs_info_sector);
    log.debug("My FS info: {}\nBarebones FS info: {}\n", .{ fs_info, barebones.fs_info });
    // Root directory empty

    const fat_lba = partition_start_lba + partition_mbr.bpb.dos3_31.dos2_0.reserved_sector_count;
    const fat_entries = try disk.read_typed_sectors(FATEntrySector, fat_lba);
    const max_valid_cluster_number = FAT32.get_maximum_valid_cluster_number(partition_mbr);
    for (fat_entries) |fat_entry| {
        if (fat_entry.value == 0) break;
        log.debug("Fat entry: {}", .{fat_entry.get_type(max_valid_cluster_number)});
    }

    const root_cluster = partition_mbr.bpb.root_directory_cluster_offset;

    const cluster_sector_count = partition_mbr.bpb.dos3_31.dos2_0.cluster_sector_count;
    const data_lba = fat_lba + (partition_mbr.bpb.fat_sector_count_32 * partition_mbr.bpb.dos3_31.dos2_0.fat_count);
    log.debug("Data LBA: 0x{x}", .{data_lba});

    for (barebones.fat_entries) |entry| {
        if (entry.value == 0) break;
        log.debug("Barebones FAT entry: {}", .{entry.get_type(max_valid_cluster_number)});
    }

    log.debug("Root FAT dir entries: {}", .{barebones.root_fat_directory_entries.len});
    for (barebones.root_fat_directory_entries) |entry| {
        if (entry.is_free()) break;
        log.debug("Barebones FAT dir entry: {}", .{entry});
    }

    assert(absolute_path[0] == '/');

    const root_cluster_sector = data_lba + cluster_sector_count * (root_cluster - root_cluster);
    var upper_cluster = root_cluster;
    var dir_tokenizer = common.std.mem.tokenize(u8, absolute_path, "/");

    var directories: u64 = 0;
    while (dir_tokenizer.next()) |entry_name| {
        defer directories += 1;
        assert(entry_name.len <= 8);
        log.debug("Looking for/creating {s}", .{entry_name});

        //const cluster_sector = directory_cluster * cluster_sector_count;
        const directory_cluster = try allocate_fat_entry(disk, partition_mbr, fs_info, partition_start_lba, write_options);
        log.debug("Directory cluster: {}", .{directory_cluster});

        log.debug("Upper cluster: {}", .{upper_cluster});
        const entry = FAT32.DirectoryEntry{
            .name = blk: {
                var name: [11]u8 = [1]u8{' '} ** 11;
                common.copy(u8, &name, entry_name);
                break :blk name;
            },
            .attributes = .{
                .read_only = false,
                .hidden = false,
                .system = false,
                .volume_id = false,
                .directory = true,
                .archive = false,
            },
            .creation_time_tenth = 169,
            .creation_time = limine_time,
            .creation_date = limine_date,
            .first_cluster_high = @truncate(u16, directory_cluster >> 16),
            .first_cluster_low = @truncate(u16, directory_cluster),
            .last_access_date = limine_date,
            .last_write_time = .{ .seconds_2_factor = 14, .minutes = 20, .hours = 18 },
            .last_write_date = limine_date,
            .file_size = 0,
        };

        var dot_entry = entry;
        dot_entry.name = dot_entry_name;
        var dot_dot_entry = entry;
        dot_dot_entry.name = dot_dot_entry_name;
        dot_dot_entry.set_first_cluster(if (upper_cluster == root_cluster) 0 else upper_cluster);

        try insert_directory_entry_slow(disk, entry, .{
            .cluster = upper_cluster,
            .root_cluster = root_cluster,
            .cluster_sector_count = cluster_sector_count,
            .root_cluster_sector = root_cluster_sector,
        });
        try insert_directory_entry_slow(disk, dot_entry, .{
            .cluster = upper_cluster + 1,
            .root_cluster = root_cluster,
            .cluster_sector_count = cluster_sector_count,
            .root_cluster_sector = root_cluster_sector,
        });
        try insert_directory_entry_slow(disk, dot_dot_entry, .{
            .cluster = upper_cluster + 1,
            .root_cluster = root_cluster,
            .cluster_sector_count = cluster_sector_count,
            .root_cluster_sector = root_cluster_sector,
        });

        upper_cluster = directory_cluster;
    }
}

fn compare_fat_entries(my_fat_entries: []const FAT32.Entry, barebones_fat_entries: []align(1) const FAT32.Entry) void {
    for (my_fat_entries) |fat_entry, fat_entry_index| {
        const barebones_fat_entry = barebones_fat_entries[fat_entry_index];
        if (barebones_fat_entry.value == .free) {
            break;
        }

        log.debug("Barebones[{}] = {}", .{ fat_entry_index, barebones_fat_entry.value });

        if (barebones_fat_entry.value != fat_entry.value) {
            log.debug("Difference at index {}. My FAT entry: {}. Barebones FAT entry: {}", .{ fat_entry_index, fat_entry, barebones_fat_entry });
        }
    }
}

pub fn get_header(disk: *Disk.Descriptor) !*GPT.Header {
    return try disk.read_typed_sectors(GPT.Header, header_lba);
}

test "gpt size" {
    comptime {
        assert(@sizeOf(Header) == 0x5c);
    }
}
