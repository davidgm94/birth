const common = @import("../../common.zig");
const GPT = common.PartitionTable.GPT;
const kb = common.kb;
const mb = common.mb;
const gb = common.gb;

pub const volumes_lba = GPT.reserved_partition_size / GPT.max_block_size / 2;
pub const minimum_partition_size = 33 * mb;
pub const maximum_partition_size = 32 * gb;

pub const FSInfo = extern struct {
    lead_signature: u32 = 0x41617272,
    reserved: [480]u8 = [1]u8{0} ** 480,
    signature: u32 = 0x61417272,
    free_cluster_count: u32,
    next_free_cluster: u32,
    reserved1: [12]u8 = [1]u8{0} ** 12,
    trail_signature: u32 = 0xaa550000,
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
