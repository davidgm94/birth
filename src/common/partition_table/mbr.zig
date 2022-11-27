const MBR = @This();

const common = @import("../../common.zig");
const assert = common.assert;

pub const BIOSParameterBlock = extern struct {
    pub const DOS2_0 = extern struct {
        jmp_code: [3]u8 = .{ 0xeb, 0x58, 0x90 },
        oem_identifier: [8]u8 = "MSWIN4.1".*,
        bytes_per_logical_sector: u16 align(1),
        logical_sectors_per_cluster: u8,
        reserved_logical_sector_count: u16,
        file_allocation_table_count: u8,
        max_fat_root_directory_entry_count: u16 align(1), // only for FAT12 and FAT16
        total_logical_sector_count: u16 align(1),
        media_descriptor: u8,
        logical_sector_count_per_fat: u16,

        comptime {
            assert(@sizeOf(@This()) == 24);
        }
    };

    pub const DOS3_31 = extern struct {
        dos2_0: DOS2_0,
        physical_sectors_per_track: u16,
        disk_head_count: u16,
        hidden_sector_count_before_partition: u32,
        total_logical_sector_count: u32,

        comptime {
            assert(@sizeOf(@This()) == 36);
        }
    };

    pub const DOS7_1_79 = extern struct {
        dos3_31: DOS3_31 align(1),
        logical_sector_count_per_fat: u32 align(1),
        drive_description: u16 align(1),
        version: u16 align(1),
        root_directory_start_cluster_count: u32 align(1),
        logical_sector_number_of_fs_information_sector: u16 align(1),
        first_logical_sector_number_of_fat_bootsectors_copy: u16 align(1),
        reserved: [12]u8 = [1]u8{0} ** 12,
        drive_number: u8,
        reserved1: u8 = 0,
        extended_boot_signature: u8,
        serial_number: u32 align(1),
        volume_label: [11]u8,
        filesystem_type: [8]u8,

        pub fn get_free_cluster_count(bpb: *const DOS7_1_79) u32 {
            const total_sector_count = bpb.dos3_31.total_logical_sector_count;
            const reserved_sector_count = bpb.dos3_31.dos2_0.reserved_logical_sector_count;
            const sector_count_per_fat = bpb.logical_sector_count_per_fat;
            const fat_count = bpb.dos3_31.dos2_0.file_allocation_table_count;
            return total_sector_count - reserved_sector_count - (sector_count_per_fat * fat_count);
        }

        comptime {
            assert(@sizeOf(@This()) == 90);
        }
    };
};

pub const Partition = packed struct(u128) {
    boot_indicator: u8,
    starting_chs: u24,
    os_type: u8,
    ending_chs: u24,
    first_lba: u32,
    size_in_lba: u32,

    comptime {
        assert(@sizeOf(@This()) == 16);
    }
};

pub const Struct = extern struct {
    bpb: BIOSParameterBlock.DOS7_1_79,
    code: [356]u8,
    partitions: [4]Partition align(2),
    signature: [2]u8 = [_]u8{ 0x55, 0xaa },

    comptime {
        assert(@sizeOf(@This()) == 0x200);
    }
};
