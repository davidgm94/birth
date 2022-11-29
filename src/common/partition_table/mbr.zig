const MBR = @This();

const common = @import("../../common.zig");
const assert = common.assert;
const log = common.log.scoped(.MBR);
const Disk = common.Disk.Descriptor;

pub const BIOSParameterBlock = extern struct {
    pub const DOS2_0 = extern struct {
        jmp_code: [3]u8 = .{ 0xeb, 0x58, 0x90 },
        oem_identifier: [8]u8,
        sector_size: u16 align(1),
        cluster_sector_count: u8,
        reserved_sector_count: u16,
        fat_count: u8,
        root_entry_count: u16 align(1), // only for FAT12 and FAT16
        total_sector_count_16: u16 align(1),
        media_descriptor: u8,
        fat_sector_count_16: u16,

        comptime {
            assert(@sizeOf(@This()) == 24);
        }
    };

    pub const DOS3_31 = extern struct {
        dos2_0: DOS2_0,
        physical_sectors_per_track: u16,
        disk_head_count: u16,
        hidden_sector_count: u32,
        total_sector_count_32: u32,

        comptime {
            assert(@sizeOf(@This()) == 36);
        }
    };

    pub const DOS7_1_79 = extern struct {
        dos3_31: DOS3_31 align(1),
        fat_sector_count_32: u32 align(1),
        drive_description: u16 align(1),
        version: [2]u8 align(1),
        root_directory_cluster_offset: u32 align(1),
        fs_info_sector: u16 align(1),
        backup_boot_record_sector: u16 align(1),
        reserved: [12]u8 = [1]u8{0} ** 12,
        drive_number: u8,
        reserved1: u8 = 0,
        extended_boot_signature: u8,
        serial_number: u32 align(1),
        volume_label: [11]u8,
        filesystem_type: [8]u8,

        pub fn get_free_cluster_count(bpb: *const DOS7_1_79) u32 {
            const total_sector_count = bpb.dos3_31.total_sector_count_32;
            const reserved_sector_count = bpb.dos3_31.dos2_0.reserved_sector_count;
            const sector_count_per_fat = bpb.fat_sector_count_32;
            const fat_count = bpb.dos3_31.dos2_0.fat_count;
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

pub const VerificationError = error{
    jmp_code,
    sector_size,
    cluster_sector_count,
    reserved_sector_count,
    fat_count,
    root_entry_count,
    total_sector_count_16,
    media_type,
    fat_sector_count_16,
    hidden_sector_count,
    total_sector_count_32,
    fat_sector_count_32,
    fat_version,
    root_directory_cluster_offset,
    fs_info_sector,
    backup_boot_record_sector,
    filesystem_type,
};

pub const Struct = extern struct {
    bpb: BIOSParameterBlock.DOS7_1_79,
    code: [356]u8,
    partitions: [4]Partition align(2),
    signature: [2]u8 = [_]u8{ 0x55, 0xaa },

    comptime {
        assert(@sizeOf(@This()) == 0x200);
    }

    pub fn compare(mbr: *Struct, other: *align(1) const Struct) void {
        log.debug("My FAT MBR:\n{}\n", .{mbr});
        log.debug("Expected FAT MBR:\n{}\n", .{other});
    }

    pub fn verify(mbr: *const Struct, disk: *Disk) VerificationError!void {
        const bpb_2_0 = mbr.bpb.dos3_31.dos2_0;
        const jmp_code = bpb_2_0.jmp_code;
        const is_allowed_jmp_code = (jmp_code[0] == 0xeb and jmp_code[2] == 0x90) or jmp_code[0] == 0xe9;
        log.debug("Checking jump code: [0x{x}, 0x{x}, 0x{x}]", .{ jmp_code[0], jmp_code[1], jmp_code[2] });
        if (!is_allowed_jmp_code) {
            return VerificationError.jmp_code;
        }

        const sector_size = bpb_2_0.sector_size;
        log.debug("Checking sector size: 0x{x}", .{sector_size});
        if (sector_size != 0x200) {
            log.warn("Sector size different than 0x200: 0x{x}", .{sector_size});
            return VerificationError.sector_size;
        }

        if (sector_size != 0x200 and sector_size != 0x400 and sector_size != 0x800 and sector_size != 0x1000) {
            return VerificationError.sector_size;
        }

        const cluster_sector_count = bpb_2_0.cluster_sector_count;
        log.debug("Checking cluster sector count: {}", .{cluster_sector_count});
        if (cluster_sector_count != 1 and cluster_sector_count != 2 and cluster_sector_count != 4 and cluster_sector_count != 8 and cluster_sector_count != 16 and cluster_sector_count != 32 and cluster_sector_count != 64 and cluster_sector_count != 128) {
            return VerificationError.cluster_sector_count;
        }

        const reserved_sector_count = bpb_2_0.reserved_sector_count;
        log.debug("Checking reserved sector count: {}", .{cluster_sector_count});
        // TODO: 32 is recommended, not mandatory
        if (reserved_sector_count != 32) {
            return VerificationError.cluster_sector_count;
        }

        const fat_count = bpb_2_0.fat_count;
        log.debug("Checking FAT count: {}", .{fat_count});
        if (fat_count != 2) {
            return VerificationError.fat_count;
        }

        const root_entry_count = bpb_2_0.root_entry_count;
        log.debug("Checking root entry count: {}", .{root_entry_count});
        if (root_entry_count != 0) {
            return VerificationError.root_entry_count;
        }

        const total_sector_count_16 = bpb_2_0.total_sector_count_16;
        log.debug("Checking total sector count (16): {}", .{total_sector_count_16});
        if (total_sector_count_16 != 0) {
            return VerificationError.total_sector_count_16;
        }

        const media_type = bpb_2_0.media_descriptor;
        log.debug("Checking media type: 0x{x}", .{media_type});
        if (media_type != 0xf8 and media_type != 0xf0) {
            log.warn("Not a standard media type: 0x{x}", .{media_type});
        }

        if (media_type != 0xf0 and media_type != 0xf8 and media_type != 0xf9 and media_type != 0xfa and media_type != 0xfb and media_type != 0xfc and media_type != 0xfd and media_type != 0xfe and media_type != 0xff) {
            return VerificationError.media_type;
        }

        const fat_sector_count_16 = bpb_2_0.fat_sector_count_16;
        log.debug("Checking FAT sector count (16): {}", .{fat_sector_count_16});
        if (fat_sector_count_16 != 0) {
            return VerificationError.fat_sector_count_16;
        }

        const bpb_3_31 = mbr.bpb.dos3_31;

        const hidden_sector_count = bpb_3_31.hidden_sector_count;
        log.debug("Checking hidden sector count: {}", .{hidden_sector_count});
        if (hidden_sector_count != 0) {
            return VerificationError.hidden_sector_count;
        }

        const total_sector_count_32 = bpb_3_31.total_sector_count_32;
        log.debug("Checking total sector count (32): {}", .{total_sector_count_32});
        if (total_sector_count_32 != @divExact(disk.disk_size, disk.sector_size)) {
            return VerificationError.total_sector_count_32;
        }

        const fat_sector_count_32 = mbr.bpb.fat_sector_count_32;
        log.debug("Checking FAT sector count (32): {}", .{fat_sector_count_32});
        if (fat_sector_count_32 == 0) {
            return VerificationError.fat_sector_count_32;
        }

        const fat_version = mbr.bpb.version;
        log.debug("Checking FAT version: {}.{}", .{ fat_version[0], fat_version[1] });
        if (fat_version[0] != 0 or fat_version[1] != 0) {
            return VerificationError.fat_version;
        }

        const root_directory_cluster_offset = mbr.bpb.root_directory_cluster_offset;
        log.debug("Checking root directory cluster offset: {}", .{root_directory_cluster_offset});
        if (root_directory_cluster_offset != 2) {
            return VerificationError.root_directory_cluster_offset;
        }

        const fs_info_sector = mbr.bpb.fs_info_sector;
        log.debug("Checking FSInfo sector: {}", .{fs_info_sector});
        if (fs_info_sector != 1) {
            return VerificationError.fs_info_sector;
        }

        const backup_boot_record_sector = mbr.bpb.backup_boot_record_sector;
        log.debug("Checking backup boot record sector: {}", .{backup_boot_record_sector});
        if (backup_boot_record_sector != 6) {
            return VerificationError.backup_boot_record_sector;
        }

        const filesystem_type = mbr.bpb.filesystem_type;
        log.debug("Checking filesystem type...", .{});
        if (!common.equal(u8, &filesystem_type, "FAT32   ")) {
            return VerificationError.filesystem_type;
        }

        unreachable;
    }

    pub fn format(mbr: *const Struct, comptime _: []const u8, _: common.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try common.internal_format(writer, "MBR:\n", .{});
        const bpb_2_0 = mbr.bpb.dos3_31.dos2_0;
        try common.internal_format(writer, "\tJump code: [0x{x}, 0x{x}, 0x{x}]\n", .{ bpb_2_0.jmp_code[0], bpb_2_0.jmp_code[1], bpb_2_0.jmp_code[2] });
        try common.internal_format(writer, "\tOEM identifier: {s}\n", .{bpb_2_0.oem_identifier});
        try common.internal_format(writer, "\tSector size: {}\n", .{bpb_2_0.sector_size});
        try common.internal_format(writer, "\tCluster sector count: {}\n", .{bpb_2_0.cluster_sector_count});
        try common.internal_format(writer, "\tReserved sector count: {}\n", .{bpb_2_0.reserved_sector_count});
        try common.internal_format(writer, "\tFAT count: {}\n", .{bpb_2_0.fat_count});
        try common.internal_format(writer, "\tRoot entry count: {}\n", .{bpb_2_0.root_entry_count});
        try common.internal_format(writer, "\tTotal sector count(16): {}\n", .{bpb_2_0.total_sector_count_16});
        try common.internal_format(writer, "\tMedia descriptor: {}\n", .{bpb_2_0.media_descriptor});
        try common.internal_format(writer, "\tFAT sector count (16): {}\n", .{bpb_2_0.fat_sector_count_16});

        const bpb_3_31 = mbr.bpb.dos3_31;
        try common.internal_format(writer, "\tPhysical sectors per track: {}\n", .{bpb_3_31.physical_sectors_per_track});
        try common.internal_format(writer, "\tDisk head count: {}\n", .{bpb_3_31.disk_head_count});
        try common.internal_format(writer, "\tHidden sector count: {}\n", .{bpb_3_31.hidden_sector_count});
        try common.internal_format(writer, "\tTotal sector count: {}\n", .{bpb_3_31.total_sector_count_32});

        const bpb_7_1_79 = mbr.bpb;

        try common.internal_format(writer, "\tFAT sector count (32): {}\n", .{bpb_7_1_79.fat_sector_count_32});
        try common.internal_format(writer, "\tDrive description: {}\n", .{bpb_7_1_79.drive_description});
        try common.internal_format(writer, "\tVersion: {}.{}\n", .{ bpb_7_1_79.version[0], bpb_7_1_79.version[1] });
        try common.internal_format(writer, "\tRoot directory cluster offset: {}\n", .{bpb_7_1_79.root_directory_cluster_offset});
        try common.internal_format(writer, "\tFS info sector: {}\n", .{bpb_7_1_79.fs_info_sector});
        try common.internal_format(writer, "\tBackup boot record sector: {}\n", .{bpb_7_1_79.backup_boot_record_sector});
        try common.internal_format(writer, "\tDriver number: {}\n", .{bpb_7_1_79.drive_number});
        try common.internal_format(writer, "\tExtended boot signature: {}\n", .{bpb_7_1_79.extended_boot_signature});
        try common.internal_format(writer, "\tSerial number: {}\n", .{bpb_7_1_79.serial_number});
        try common.internal_format(writer, "\tVolume label: {s}\n", .{bpb_7_1_79.volume_label});
        try common.internal_format(writer, "\tFilesystem type: {s}\n", .{bpb_7_1_79.filesystem_type});

        try common.internal_format(writer, "\nCode:\n", .{});
        for (mbr.code) |code_byte| {
            try common.internal_format(writer, "0x{x}, ", .{code_byte});
        }

        try common.internal_format(writer, "\n\nPartitions:\n", .{});
        for (mbr.partitions) |partition, partition_index| {
            if (partition.size_in_lba != 0) {
                try common.internal_format(writer, "[{}]\n", .{partition_index});
                try common.internal_format(writer, "\tBoot indicator: 0x{x}\n", .{partition.boot_indicator});
                try common.internal_format(writer, "\tStarting CHS: 0x{x}\n", .{partition.starting_chs});
                try common.internal_format(writer, "\tOS type: 0x{x}\n", .{partition.os_type});
                try common.internal_format(writer, "\tEnding CHS: 0x{x}\n", .{partition.ending_chs});
                try common.internal_format(writer, "\tFirst LBA: 0x{x}\n", .{partition.first_lba});
                try common.internal_format(writer, "\tSize in LBA: 0x{x}\n", .{partition.size_in_lba});
            }
        }
    }
};
