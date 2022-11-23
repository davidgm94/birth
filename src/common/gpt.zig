const common = @import("../common.zig");
const assert = common.assert;
const expect = common.testing.expect;
pub const Header = extern struct {
    signature: [8]u8 = "EFI PART".*,
    revision: u32,
    header_size: u32,
    header_crc32: u32,
    reserved: u32 = 0,
    current_lba: u64 align(4),
    backup_lba: u64 align(4),
    first_usable_lba: u64 align(4),
    last_usable_lba: u64 align(4),
    disk_guid: [16]u8,
    partition_entry_array_starting_lba: u64 align(4),
    partition_entry_count: u32,
    partition_entry_size: u32,
    partition_entry_array_crc32: u32,

    comptime {
        assert(@sizeOf(Header) == 0x5c);
    }
};
