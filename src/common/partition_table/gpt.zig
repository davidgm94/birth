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
        .disk_guid = get_random_guid(),
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
        .unique_partition_guid = get_random_guid(),
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

pub fn format(disk: *Disk.Descriptor, partition_index: usize, filesystem: common.Filesystem.Type, write_options: Disk.Descriptor.WriteOptions) !void {
    _ = write_options;
    assert(filesystem == .fat32);
    const header = try get_header(disk);
    if (partition_index < header.partition_entry_count) {
        const partition_entry_size = header.partition_entry_size;
        assert(disk.sector_size >= partition_entry_size);
        const partition_entry_array_lba = header.partition_array_lba;
        assert(disk.sector_size % partition_entry_size == 0);
        const partition_entry_per_sector_count = @divExact(disk.sector_size, partition_entry_size);
        const partition_entry_lba = (partition_index / partition_entry_per_sector_count) + partition_entry_array_lba;
        const partition_offset_from_lba = partition_index % partition_entry_per_sector_count;
        const partition_entry_sector = try disk.callbacks.read(disk, 1, partition_entry_lba);
        const partition_entry = @ptrCast(*GPT.Partition, @alignCast(@alignOf(GPT.Partition), partition_entry_sector[partition_offset_from_lba..]));
        const partition_lba_start = partition_entry.first_lba;
        const fs_info = try disk.read_typed_sectors(FAT32.FSInfo, partition_lba_start);
        fs_info.* = .{
            .free_cluster_count = 126943,
            .next_free_cluster = 2,
        };
        log.debug("Fs info: {}", .{fs_info});
        //const partition_lba_end = partition_entry.first_lba;
        //const lba_count = partition_lba_end - partition_lba_start;
        //const fat_partition_mbr = try disk.read_typed_sectors(MBR.Struct, partition_lba_start);
        //fat_partition_mbr.* = MBR.Struct{
        //.bpb = .{
        //.dos3_31 = .{
        //.dos2_0 = .{
        //.jmp_code = .{ 0xeb, 0x58, 0x90 },
        //.oem_identifier = "rise_efi",
        //.sector_size = disk.sector_size,
        //.cluster_sector_count = @divExact(get_cluster_size(lba_count * disk.sector_size), disk.sector_size),
        //.reserved_sector_count = 32,
        //.fat_count = 2,
        //.root_entry_count = 0,
        //.total_sector_count_16 = 0,
        //.media_descriptor = 0xf8,
        //.fat_sector_count_16 = 0,
        //},
        //.physical_sectors_per_track = 32,
        //.disk_head_count = 8,
        //.hidden_sector_count = partition_lba_start, // TODO: is this right?
        //.total_sector_count_32 = lba_count,
        //},
        //},
        //};
        //log.debug("partition mbr: {}", .{fat_partition_mbr});
    } else {
        @panic("wtf");
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
