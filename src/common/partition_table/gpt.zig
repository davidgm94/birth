const common = @import("../../common.zig");
const assert = common.assert;

pub const reserved_partition_size = 1 * common.mb;
pub const max_partition_count = 128;
pub const partition_array_size = 16 * common.kb;
pub const min_block_size = 0x200;
pub const max_block_size = 0x1000;
pub const partition_array_lba_start = 2;
pub const header_lba = 1;

pub const Header = extern struct {
    signature: [8]u8 = "EFI PART".*,
    revision: [4]u8 = .{ 0, 0, 1, 0 },
    header_size: u32 = @sizeOf(Header),
    header_crc32: u32 = 0,
    reserved: u32 = 0,
    current_lba: u64 align(4),
    backup_lba: u64 align(4),
    first_usable_lba: u64 align(4),
    last_usable_lba: u64 align(4),
    disk_guid: GUID,
    partition_entry_array_starting_lba: u64 align(4) = partition_array_lba_start,
    partition_entry_count: u32 = max_partition_count,
    partition_entry_size: u32 = @sizeOf(Partition),
    partition_entry_array_crc32: u32,
    reserved1: [417]u8 = [1]u8{0} ** 417,

    comptime {
        assert(@sizeOf(Header) == 0x200);
    }
};

pub const GUID = extern struct {
    time_low: u32,
    time_mid: u16,
    time_hi_and_version: u16,
    clock_seq_hi_and_reserved: u8,
    clock_seq_low: u8,
    node: [6]u8,

    pub fn get_random() GUID {
        const random_array = blk: {
            var arr: [16]u8 = undefined;
            var prng = common.std.rand.DefaultPrng.init(0);
            const random = prng.random();
            random.bytes(&arr);
            break :blk arr;
        };
        var guid = GUID{
            .time_low = (@as(u32, random_array[0]) << 24) | (@as(u32, random_array[1]) << 16) | (@as(u32, random_array[2]) << 8) | random_array[3],
            .time_mid = (@as(u16, random_array[4]) << 8) | random_array[5],
            .time_hi_and_version = (@as(u16, random_array[6]) << 8) | random_array[7],
            .clock_seq_hi_and_reserved = random_array[8],
            .clock_seq_low = random_array[9],
            .node = .{ random_array[10], random_array[11], random_array[12], random_array[13], random_array[14], random_array[15] },
        };

        guid.clock_seq_hi_and_reserved = (2 << 6) | (guid.clock_seq_hi_and_reserved >> 2);
        guid.time_hi_and_version = (4 << 12) | (guid.time_hi_and_version >> 4);

        return guid;
    }
};

pub const efi_system_partition_guid = GUID{ .time_low = 0xC12A7328, .time_mid = 0xF81F, .time_hi_and_version = 0x11D2, .clock_seq_hi_and_reserved = 0xBA, .clock_seq_low = 0x4B, .node = [_]u8{ 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B } };
pub const microsoft_basic_data_partition_guid = GUID{ .time_low = 0xEBD0A0A2, .time_mid = 0xB9E5, .time_hi_and_version = 0x4433, .clock_seq_hi_and_reserved = 0x87, .clock_seq_low = 0xC0, .node = [_]u8{ 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7 } };

pub const Partition = extern struct {
    partition_type_guid: GUID,
    unique_partition_guid: GUID,
    first_lba: u64,
    last_lba: u64,
    attribute_flags: [8]u8,
    partition_name: [36]u16,
};

test "gpt size" {
    comptime {
        assert(@sizeOf(Header) == 0x5c);
    }
}
