const lib = @import("lib");
const assert = lib.assert;
const FAT32 = lib.Filesystem.FAT32;
const PartitionTable = lib.PartitionTable;
const GPT = PartitionTable.GPT;
const MBR = PartitionTable.MBR;
const host = @import("host");

pub const ImageDescription = struct {
    partition_name: []const u8,
    partition_start_lba: u64,
    disk_sector_count: u64,
    disk_sector_size: u64,
    partition_filesystem: lib.FilesystemType,
};

pub extern fn deploy(device_path: [*:0]const u8, limine_hdd_ptr: [*]const u8, limine_hdd_len: usize) callconv(.C) c_int;

const Disk = lib.Disk;
pub const DiskImage = extern struct {
    disk: Disk,
    buffer_ptr: [*]u8,

    pub fn write(disk: *Disk, bytes: []const u8, sector_offset: u64, commit_memory_to_disk: bool) Disk.WriteError!void {
        const need_write = !(disk.type == .memory and !commit_memory_to_disk);
        if (need_write) {
            const disk_image = @fieldParentPtr(DiskImage, "disk", disk);
            assert(disk_image.disk.disk_size > 0);
            //assert(disk.disk.partition_count == 1);
            assert(bytes.len > 0);
            //assert(disk.disk.disk_size == disk.buffer.items.len);
            const byte_offset = sector_offset * disk_image.disk.sector_size;

            if (byte_offset + bytes.len > disk_image.disk.disk_size) return Disk.WriteError.disk_size_overflow;

            @memcpy(disk_image.getBuffer()[byte_offset .. byte_offset + bytes.len], bytes);
        }
    }

    pub fn read(disk: *Disk, sector_count: u64, sector_offset: u64, provided_buffer: ?[]const u8) Disk.ReadError!Disk.ReadResult {
        assert(provided_buffer == null);
        const disk_image = @fieldParentPtr(DiskImage, "disk", disk);
        assert(disk_image.disk.disk_size > 0);
        assert(sector_count > 0);
        //assert(disk.disk.disk_size == disk.buffer.items.len);
        const byte_count = sector_count * disk_image.disk.sector_size;
        const byte_offset = sector_offset * disk_image.disk.sector_size;
        if (byte_offset + byte_count > disk.disk_size) {
            return Disk.ReadError.read_error;
        }
        return .{
            .buffer = disk_image.getBuffer()[byte_offset .. byte_offset + byte_count].ptr,
            .sector_count = sector_count,
        };
    }

    pub fn readCache(disk: *Disk, sector_count: u64, sector_offset: u64) Disk.ReadError!Disk.ReadResult {
        _ = sector_count;
        _ = sector_offset;
        _ = disk;
        return error.read_error;
    }

    pub fn fromZero(sector_count: usize, sector_size: u16) !DiskImage {
        const disk_bytes = try host.allocateZeroMemory(sector_count * sector_size);
        var disk_image = DiskImage{
            .disk = .{
                .type = .memory,
                .callbacks = .{
                    .read = DiskImage.read,
                    .write = DiskImage.write,
                    .readCache = DiskImage.readCache,
                },
                .disk_size = disk_bytes.len,
                .sector_size = sector_size,
                .cache_size = 0,
            },
            .buffer_ptr = disk_bytes.ptr,
        };

        return disk_image;
    }

    pub fn createFAT(disk_image: *DiskImage, comptime image: ImageDescription, original_gpt_cache: ?GPT.Partition.Cache) !GPT.Partition.Cache {
        const gpt_cache = try GPT.create(&disk_image.disk, if (original_gpt_cache) |o_gpt_cache| o_gpt_cache.gpt.header else null);
        const partition_name_u16 = lib.unicode.utf8ToUtf16LeStringLiteral(image.partition_name);
        const gpt_partition_cache = try gpt_cache.addPartition(image.partition_filesystem, partition_name_u16, image.partition_start_lba, gpt_cache.header.last_usable_lba, if (original_gpt_cache) |o_gpt_cache| o_gpt_cache.partition else null);

        return gpt_partition_cache;
    }

    pub fn fromFile(file_path: []const u8, sector_size: u16, allocator: lib.ZigAllocator) !DiskImage {
        const disk_memory = try host.cwd().readFileAlloc(allocator, file_path, lib.maxInt(usize));

        var disk_image = DiskImage{
            .disk = .{
                .type = .memory,
                .callbacks = .{
                    .read = DiskImage.read,
                    .write = DiskImage.write,
                    .readCache = DiskImage.readCache,
                },
                .disk_size = disk_memory.len,
                .sector_size = sector_size,
                .cache_size = 0,
            },
            .buffer_ptr = disk_memory.ptr,
        };

        return disk_image;
    }

    const File = struct {
        handle: lib.File,
        size: usize,
    };

    pub inline fn getBuffer(disk_image: DiskImage) []u8 {
        return disk_image.buffer_ptr[0..disk_image.disk.disk_size];
    }
};

pub fn format(disk: *Disk, partition_range: Disk.PartitionRange, copy_mbr: ?*const MBR.Partition) !FAT32.Cache {
    if (disk.type != .memory) @panic("disk is not memory");
    const fat_partition_mbr_lba = partition_range.first_lba;
    const fat_partition_mbr = try disk.readTypedSectors(MBR.Partition, fat_partition_mbr_lba, null, .{});

    const sectors_per_track = 32;
    const total_sector_count_32 = @as(u32, @intCast(lib.alignBackward(u64, partition_range.last_lba - partition_range.first_lba, sectors_per_track)));
    const fat_count = FAT32.count;

    var cluster_size: u8 = 1;
    const max_cluster_size = 128;
    var fat_data_sector_count: u32 = undefined;
    var fat_length_32: u32 = undefined;
    var cluster_count_32: u32 = undefined;

    while (true) {
        assert(cluster_size > 0);
        fat_data_sector_count = total_sector_count_32 - lib.alignForward(u32, FAT32.default_reserved_sector_count, cluster_size);
        cluster_count_32 = (fat_data_sector_count * disk.sector_size + fat_count * 8) / (cluster_size * disk.sector_size + fat_count * 4);
        fat_length_32 = lib.alignForward(u32, cdiv((cluster_count_32 + 2) * 4, disk.sector_size), cluster_size);
        cluster_count_32 = (fat_data_sector_count - fat_count * fat_length_32) / cluster_size;
        const max_cluster_size_32 = @min(fat_length_32 * disk.sector_size / 4, FAT32.getMaxCluster(.fat32));
        if (cluster_count_32 > max_cluster_size_32) {
            cluster_count_32 = 0;
        }
        if (cluster_count_32 != 0 and cluster_count_32 < FAT32.getMinCluster(.fat32)) {
            cluster_count_32 = 0;
        }

        if (cluster_count_32 != 0) break;

        cluster_size <<= 1;

        const keep_going = cluster_size != 0 and cluster_size <= max_cluster_size;
        if (!keep_going) break;
        @panic("unexpected fat32 bug");
    }

    var root_directory_entries: u64 = 0;
    _ = root_directory_entries;

    const reserved_sector_count = lib.alignForward(u16, FAT32.default_reserved_sector_count, cluster_size);

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
                .hidden_sector_count = @as(u32, @intCast(partition_range.first_lba)),
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
            .serial_number = if (copy_mbr) |copy_partition_mbr| copy_partition_mbr.bpb.serial_number else @truncate(@as(u64, @intCast(host.time.microTimestamp()))),
            .volume_label = "NO NAME    ".*,
            .filesystem_type = "FAT32   ".*,
        },
        .code = [_]u8{
            0xe, 0x1f, 0xbe, 0x77, 0x7c, 0xac, 0x22, 0xc0, 0x74, 0xb, 0x56, 0xb4, 0xe, 0xbb, 0x7, 0x0, 0xcd, 0x10, 0x5e, 0xeb, 0xf0, 0x32, 0xe4, 0xcd, 0x16, 0xcd, 0x19, 0xeb, 0xfe, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x61, 0x20, 0x62, 0x6f, 0x6f, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x64, 0x69, 0x73, 0x6b, 0x2e, 0x20, 0x20, 0x50, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x20, 0x69, 0x6e, 0x73, 0x65, 0x72, 0x74, 0x20, 0x61, 0x20, 0x62, 0x6f, 0x6f, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x66, 0x6c, 0x6f, 0x70, 0x70, 0x79, 0x20, 0x61, 0x6e, 0x64, 0xd, 0xa, 0x70, 0x72, 0x65, 0x73, 0x73, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x74, 0x6f, 0x20, 0x74, 0x72, 0x79, 0x20, 0x61, 0x67, 0x61, 0x69, 0x6e, 0x20, 0x2e, 0x2e, 0x2e, 0x20, 0xd, 0xa,
        } ++ [1]u8{0} ** 227,
        // This should be zero
        .partitions = lib.zeroes([4]MBR.LegacyPartition),
    };

    try disk.writeTypedSectors(MBR.Partition, fat_partition_mbr, fat_partition_mbr_lba, false);

    const backup_boot_record_sector = partition_range.first_lba + fat_partition_mbr.bpb.backup_boot_record_sector;
    const backup_boot_record = try disk.readTypedSectors(MBR.Partition, backup_boot_record_sector, null, .{});
    backup_boot_record.* = fat_partition_mbr.*;
    try disk.writeTypedSectors(MBR.Partition, backup_boot_record, backup_boot_record_sector, false);

    const fs_info_lba = partition_range.first_lba + fat_partition_mbr.bpb.fs_info_sector;
    const fs_info = try disk.readTypedSectors(FAT32.FSInfo, fs_info_lba, null, .{});
    fs_info.* = .{
        .lead_signature = 0x41615252,
        .signature = 0x61417272,
        .free_cluster_count = cluster_count_32,
        .last_allocated_cluster = 0,
        .trail_signature = 0xaa550000,
    };
    try disk.writeTypedSectors(FAT32.FSInfo, fs_info, fs_info_lba, false);

    const cache = FAT32.Cache{
        .disk = disk,
        .partition_range = partition_range,
        .mbr = fat_partition_mbr,
        .fs_info = fs_info,
        .allocator = null,
    };

    // TODO: write this properly

    try cache.registerCluster(0, FAT32.Entry.reserved_and_should_not_be_used_eof, null);
    try cache.registerCluster(1, FAT32.Entry.allocated_and_eof, null);
    try cache.registerCluster(2, FAT32.Entry.reserved_and_should_not_be_used_eof, null);

    cache.fs_info.last_allocated_cluster = 2;
    cache.fs_info.free_cluster_count = cluster_count_32 - 1;

    const backup_fs_info_lba = backup_boot_record_sector + backup_boot_record.bpb.fs_info_sector;
    const backup_fs_info = try disk.readTypedSectors(FAT32.FSInfo, backup_fs_info_lba, null, .{});
    backup_fs_info.* = fs_info.*;
    try disk.writeTypedSectors(FAT32.FSInfo, backup_fs_info, backup_fs_info_lba, false);

    return cache;
}

fn cdiv(a: u32, b: u32) u32 {
    return (a + b - 1) / b;
}
