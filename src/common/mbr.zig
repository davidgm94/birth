const common = @import("../common.zig");
const assert = common.assert;

const BIOSParameterBlock = extern struct {
    const DOS2_0 = extern struct {
        bytes_per_logical_sector: u16 align(1),
        logical_sectors_per_cluster: u8,
        reserved_logical_sector_count: u16 align(1),
        file_allocation_table_count: u8,
        max_fat_root_directory_entry_count: u16 align(1), // only for FAT12 and FAT16
        total_logical_sector_count: u16 align(1),
        media_descriptor: u8,
        logical_sector_count_per_fat: u16 align(1),
    };

    const DOS3_0 = extern struct {
        dos2_0: DOS2_0,
        physical_sectors_per_track: u16 align(1),
        disk_head_count: u16 align(1),
        hidden_sector_count_before_partition: u16 align(1),
    };

    const DOS3_2 = extern struct {
        dos3_0: DOS3_0,
        total_logical_sector_count_including_hidden: u16 align(1),
    };

    const DOS3_31 = extern struct {
        dos2_0: DOS2_0,
        physical_sectors_per_track: u16 align(1),
        disk_head_count: u16 align(1),
        hidden_sector_count_before_partition: u32 align(1),
        total_logical_sector_count: u32 align(1),
    };

    const Extended = extern struct {
        dos3_31: DOS3_31,
        physical_drive_number: u8,
        reserved: u8,
        extended_boot_signature: u8,
        volume_id: u32 align(1),
        partition_volume_label: [11]u8,
        file_system_type: [8]u8,
    };

    const FAT32Extended = extern struct {
        dos3_31: DOS3_31,
        logical_sector_count_per_fat: u32 align(1),
        drive_description: u16 align(1),
        version: u16 align(1),
        root_directory_start_cluster_count: u32 align(1),
        logical_sector_number_of_fs_information_sector: u16 align(1),
        first_logical_sector_number_of_fat_bootsectors_copy: u16 align(1),
        reserved: [12]u8,
        cf0x024: u8,
        cf0x025: u8,
        cf0x026: u8,
        cf0x027: u32 align(1),
        cf0x02b: [11]u8,
        cf0x036: [8]u8,
    };
};

test "bpb" {
    comptime {
        assert(@sizeOf(BIOSParameterBlock.DOS2_0) == 13);
        assert(@sizeOf(BIOSParameterBlock.DOS3_0) == 19);
        assert(@sizeOf(BIOSParameterBlock.DOS3_2) == 21);
        assert(@sizeOf(BIOSParameterBlock.DOS3_31) == 25);
        assert(@sizeOf(BIOSParameterBlock.Extended) == 51);
        assert(@sizeOf(BIOSParameterBlock.FAT32Extended) == 79);
    }
}
