const common = @import("../../common.zig");
const assert = common.assert;
const Disk = common.Disk.Descriptor;
const GPT = common.PartitionTable.GPT;
const MBR = common.PartitionTable.MBR;
const kb = common.kb;
const mb = common.mb;
const gb = common.gb;
const log = common.log.scoped(.FAT32);

pub const volumes_lba = GPT.reserved_partition_size / GPT.max_block_size / 2;
pub const minimum_partition_size = 33 * mb;
pub const maximum_partition_size = 32 * gb;
pub const last_cluster = 0xffff_ffff;

pub const FSInfo = extern struct {
    lead_signature: u32 = 0x41617272,
    reserved: [480]u8 = [1]u8{0} ** 480,
    signature: u32 = 0x61417272,
    free_cluster_count: u32,
    next_free_cluster: u32,
    reserved1: [12]u8 = [1]u8{0} ** 12,
    trail_signature: u32 = 0xaa550000,
};

const FATType = enum(u8) {
    fat32,
};

pub const Partition = extern struct {
    disk: *Disk,
    mbr: *MBR.Struct,
    partition_mbr: *MBR.Struct,
    fat_begin_lba: u32,
    cluster_begin_lba: u32,
    index: u8,
    fat_type: FATType = .fat32,

    const CreateFileError = error{
        directories_not_implemented,
    };

    pub fn create_file(partition: *Partition, path: []const u8) !void {
        const is_directory_root = !common.std.mem.containsAtLeast(u8, path, 1, "/");
        if (!is_directory_root) return CreateFileError.directories_not_implemented;
        const parent_cluster = blk: {
            if (is_directory_root) {
                break :blk partition.get_root_cluster();
            } else {
                unreachable;
            }
        };

        const file_entry = try partition.get_file_entry(parent_cluster, path);
        _ = file_entry;

        unreachable;
    }

    pub fn get_root_cluster(partition: *const Partition) u32 {
        return partition.mbr.bpb.root_directory_start_cluster_count;
    }

    pub fn get_file_entry(partition: *const Partition, cluster: u32, filename: []const u8) !void {
        _ = filename;

        var offset: u32 = 0;
        assert(partition.disk.sector_size == 0x200);
        var buffer: [0x200]u8 = undefined;

        while (true) : (offset += 1) {
            if (partition.read_from_cluster_offset(cluster, offset, &buffer)) {
                unreachable;
            } else |_| {
                break;
            }
        }

        unreachable;
    }

    const ReadError = error{
        read_error,
    };

    pub fn read_from_cluster_offset(partition: *const Partition, start_cluster: u32, offset: u32, buffer: []u8) !void {
        assert(partition.fat_type == .fat32);
        var cluster_chain = start_cluster;
        const sectors_per_cluster = partition.mbr.bpb.dos3_31.dos2_0.logical_sectors_per_cluster;
        const cluster_to_read = offset / sectors_per_cluster;
        const sector_to_read = offset - (cluster_to_read * sectors_per_cluster);
        _ = sector_to_read;

        log.debug("Cluster to read: {}", .{cluster_to_read});

        var cluster_i: u64 = 0;
        while (cluster_i < cluster_to_read) : (cluster_i += 1) {
            cluster_chain = partition.find_next_cluster(cluster_chain);
        }

        if (cluster_chain == last_cluster) {
            return ReadError.read_error;
        }

        // TODO: eliminate intermediate buffer
        const lba = partition.lba_of_cluster(cluster_chain);
        log.debug("Trying to read LBA {}", .{lba});
        const disk_buffer = try partition.disk.callbacks.read(partition.disk, 1, lba);
        common.copy(u8, buffer, disk_buffer);
        unreachable;
    }

    fn lba_of_cluster(partition: *const Partition, cluster: u32) u32 {
        assert(partition.fat_type == .fat32);
        log.debug("Getting LBA for cluster {}", .{cluster});
        const result = partition.cluster_begin_lba + ((cluster - 2) * partition.mbr.bpb.dos3_31.dos2_0.logical_sectors_per_cluster);
        if (true) unreachable;
        return result;
    }

    pub fn find_next_cluster(partition: *const Partition, current_cluster: u32) u32 {
        log.debug("Finding next cluster from current: {}...", .{current_cluster});
        var cluster = current_cluster;
        if (cluster == 0) cluster = 2;

        const fat_sector_offset = @divExact(cluster, 128);
        const sector = partition.mbr.partitions[partition.index].first_lba + partition.mbr.bpb.dos3_31.dos2_0.reserved_logical_sector_count + fat_sector_offset;
        var buffer: [0x200]u8 = undefined;
        partition.read_sector(sector, &buffer) catch return last_cluster;
        unreachable;
    }

    pub fn read_sector(partition: *const Partition, sector: u32, buffer: []u8) !void {
        assert(buffer.len >= partition.disk.sector_size);
        const disk_buffer = try partition.disk.callbacks.read(partition.disk, sector, partition.disk.sector_size);
        common.copy(u8, buffer, disk_buffer);
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

pub fn get_cluster_size(partition_size: u64) u16 {
    if (partition_size <= 64 * mb) return 0x200;
    if (partition_size <= 128 * mb) return 1 * kb;
    if (partition_size <= 256 * mb) return 2 * kb;
    if (partition_size <= 8 * gb) return 8 * kb;
    if (partition_size <= 16 * gb) return 16 * kb;

    return 32 * kb;
}

pub fn get_size(total_sector_count: u32, reserved_sector_count: u16, sectors_per_cluster: u8, fat_count: u8) u32 {
    const magic = (128 * sectors_per_cluster) + fat_count / 2;
    const fat_size = (total_sector_count - reserved_sector_count + magic - 1) / magic;

    return fat_size;
}
