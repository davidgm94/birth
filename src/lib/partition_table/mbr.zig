const MBR = @This();

const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.MBR);
const Disk = lib.Disk.Descriptor;
const GPT = lib.PartitionTable.GPT;
const FAT32 = lib.Filesystem.FAT32;

pub const default_lba = 0;

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

        fn compare(bpb_2_0: *const DOS2_0, other: *align(1) const DOS2_0) void {
            if (!lib.equal(u8, &bpb_2_0.jmp_code, &other.jmp_code)) log.debug("Jump code differs: {any}, {any}", .{ bpb_2_0.jmp_code, other.jmp_code });
            if (!lib.equal(u8, &bpb_2_0.oem_identifier, &other.oem_identifier)) log.debug("OEM identifier differs: {any}, {any}", .{ bpb_2_0.oem_identifier, other.oem_identifier });
            if (bpb_2_0.sector_size != other.sector_size) log.debug("Sector size differs: {}, {}", .{ bpb_2_0.sector_size, other.sector_size });
            if (bpb_2_0.cluster_sector_count != other.cluster_sector_count) log.debug("Cluster sector count differs: {}, {}", .{ bpb_2_0.cluster_sector_count, other.cluster_sector_count });
            if (bpb_2_0.reserved_sector_count != other.reserved_sector_count) log.debug("Reserved sector count differs: {}, {}", .{ bpb_2_0.reserved_sector_count, other.reserved_sector_count });
            if (bpb_2_0.fat_count != other.fat_count) log.debug("FAT count differs: {}, {}", .{ bpb_2_0.fat_count, other.fat_count });
            if (bpb_2_0.root_entry_count != other.root_entry_count) log.debug("Root entry count differs: {}, {}", .{ bpb_2_0.root_entry_count, other.root_entry_count });
            if (bpb_2_0.total_sector_count_16 != other.total_sector_count_16) log.debug("Total sector count(16) differs: {}, {}", .{ bpb_2_0.total_sector_count_16, other.total_sector_count_16 });
            if (bpb_2_0.media_descriptor != other.media_descriptor) log.debug("Media descriptor differs: {}, {}", .{ bpb_2_0.media_descriptor, other.media_descriptor });
            if (bpb_2_0.fat_sector_count_16 != other.fat_sector_count_16) log.debug("FAT sector count (16) differs: {}, {}", .{ bpb_2_0.fat_sector_count_16, other.fat_sector_count_16 });
        }
    };

    pub const DOS3_31 = extern struct {
        dos2_0: DOS2_0,
        physical_sectors_per_track: u16,
        disk_head_count: u16,
        hidden_sector_count: u32,
        total_sector_count_32: u32,

        fn compare(bpb_3_31: *align(1) const DOS3_31, other: *align(1) const DOS3_31) void {
            bpb_3_31.dos2_0.compare(&other.dos2_0);

            if (bpb_3_31.physical_sectors_per_track != other.physical_sectors_per_track) log.debug("Physical sectors per track differs: {}, {}", .{ bpb_3_31.physical_sectors_per_track, other.physical_sectors_per_track });
            if (bpb_3_31.disk_head_count != other.disk_head_count) log.debug("Disk head count differs: {}, {}", .{ bpb_3_31.disk_head_count, other.disk_head_count });
            if (bpb_3_31.hidden_sector_count != other.hidden_sector_count) log.debug("Hidden sector count differs: {}, {}", .{ bpb_3_31.hidden_sector_count, other.hidden_sector_count });
            if (bpb_3_31.total_sector_count_32 != other.total_sector_count_32) log.debug("Total sector count differs: {}, {}", .{ bpb_3_31.total_sector_count_32, other.total_sector_count_32 });
        }

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

        fn compare(this: *const DOS7_1_79, other: *align(1) const DOS7_1_79) void {
            this.dos3_31.compare(&other.dos3_31);

            if (this.fat_sector_count_32 != other.fat_sector_count_32) log.debug("FAT sector count (32) differs: {}, {}", .{ this.fat_sector_count_32, other.fat_sector_count_32 });
            if (this.drive_description != other.drive_description) log.debug("Drive description differs: {}, {}", .{ this.drive_description, other.drive_description });
            if (!lib.equal(u8, &this.version, &other.version)) log.debug("Version differs: {any}, {any}", .{ this.version, other.version });
            if (this.root_directory_cluster_offset != other.root_directory_cluster_offset) log.debug("Root directory cluster differs: {}, {}", .{ this.root_directory_cluster_offset, other.root_directory_cluster_offset });
            if (this.fs_info_sector != other.fs_info_sector) log.debug("FS info differs: {}, {}", .{ this.fs_info_sector, other.fs_info_sector });
            if (this.backup_boot_record_sector != other.backup_boot_record_sector) log.debug("Backup boot record sector differs: {}, {}", .{ this.backup_boot_record_sector, other.backup_boot_record_sector });
            if (this.drive_number != other.drive_number) log.debug("Drive number differs: {}, {}", .{ this.drive_number, other.drive_number });
            if (this.extended_boot_signature != other.extended_boot_signature) log.debug("Extended boot signature differs: {}, {}", .{ this.extended_boot_signature, other.extended_boot_signature });
            if (this.serial_number != other.serial_number) log.debug("Serial number differs: 0x{x}, 0x{x}", .{ this.serial_number, other.serial_number });
            if (!lib.equal(u8, &this.volume_label, &other.volume_label)) log.debug("Volume label differs: {s}, {s}", .{ this.volume_label, other.volume_label });
            if (!lib.equal(u8, &this.filesystem_type, &other.filesystem_type)) log.debug("Filesystem type differs: {s}, {s}", .{ this.filesystem_type, other.filesystem_type });
        }

        comptime {
            assert(@sizeOf(@This()) == 90);
        }
    };
};

pub const LegacyPartition = packed struct(u128) {
    boot_indicator: u8,
    starting_chs: u24,
    os_type: u8,
    ending_chs: u24,
    first_lba: u32,
    size_in_lba: u32,

    comptime {
        assert(@sizeOf(@This()) == 0x10);
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

pub const Partition = extern struct {
    bpb: BIOSParameterBlock.DOS7_1_79,
    code: [356]u8,
    partitions: [4]LegacyPartition align(2),
    signature: [2]u8 = [_]u8{ 0x55, 0xaa },

    comptime {
        assert(@sizeOf(@This()) == lib.default_sector_size);
    }

    pub fn compare(mbr: *Partition, other: *MBR.Partition) void {
        log.debug("Comparing MBRs...", .{});
        mbr.bpb.compare(&other.bpb);

        if (!lib.equal(u8, &mbr.code, &other.code)) {
            @panic("mbr: code does not match");
        }

        for (mbr.partitions, 0..) |this_partition, partition_i| {
            const other_partition = other.partitions[partition_i];

            if (this_partition.boot_indicator != other_partition.boot_indicator) log.debug("Mismatch: {}, .{}", .{ this_partition.boot_indicator, other_partition.boot_indicator });
            if (this_partition.starting_chs != other_partition.starting_chs) log.debug("Mismatch: {}, .{}", .{ this_partition.starting_chs, other_partition.starting_chs });
            if (this_partition.os_type != other_partition.os_type) log.debug("Mismatch: {}, .{}", .{ this_partition.os_type, other_partition.os_type });
            if (this_partition.ending_chs != other_partition.ending_chs) log.debug("Mismatch: {}, .{}", .{ this_partition.ending_chs, other_partition.ending_chs });
            if (this_partition.first_lba != other_partition.first_lba) log.debug("Mismatch: {}, .{}", .{ this_partition.first_lba, other_partition.first_lba });
            if (this_partition.size_in_lba != other_partition.size_in_lba) log.debug("Mismatch: {}, .{}", .{ this_partition.size_in_lba, other_partition.size_in_lba });
        }
    }

    pub fn verify(mbr: *const MBR.Partition, disk: *Disk) VerificationError!void {
        const bpb_2_0 = mbr.bpb.dos3_31.dos2_0;
        const jmp_code = bpb_2_0.jmp_code;
        const is_allowed_jmp_code = (jmp_code[0] == 0xeb and jmp_code[2] == 0x90) or jmp_code[0] == 0xe9;
        log.debug("Checking jump code: [0x{x}, 0x{x}, 0x{x}]", .{ jmp_code[0], jmp_code[1], jmp_code[2] });
        if (!is_allowed_jmp_code) {
            return VerificationError.jmp_code;
        }

        const sector_size = bpb_2_0.sector_size;
        log.debug("Checking sector size: 0x{x}", .{sector_size});
        if (sector_size != lib.default_sector_size) {
            log.warn("Sector size different than 0x{x}: 0x{x}", .{ lib.default_sector_size, sector_size });
            return VerificationError.sector_size;
        }

        if (sector_size != lib.default_sector_size and sector_size != 0x400 and sector_size != 0x800 and sector_size != 0x1000) {
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
        if (!lib.equal(u8, &filesystem_type, "FAT32   ")) {
            return VerificationError.filesystem_type;
        }

        @panic("mbr: unexpected verification error");
    }

    pub fn format(mbr: *const MBR.Partition, comptime _: []const u8, _: lib.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try lib.format(writer, "MBR:\n", .{});
        const bpb_2_0 = mbr.bpb.dos3_31.dos2_0;
        try lib.format(writer, "\tJump code: [0x{x}, 0x{x}, 0x{x}]\n", .{ bpb_2_0.jmp_code[0], bpb_2_0.jmp_code[1], bpb_2_0.jmp_code[2] });
        try lib.format(writer, "\tOEM identifier: {s}\n", .{bpb_2_0.oem_identifier});
        try lib.format(writer, "\tSector size: {}\n", .{bpb_2_0.sector_size});
        try lib.format(writer, "\tCluster sector count: {}\n", .{bpb_2_0.cluster_sector_count});
        try lib.format(writer, "\tReserved sector count: {}\n", .{bpb_2_0.reserved_sector_count});
        try lib.format(writer, "\tFAT count: {}\n", .{bpb_2_0.fat_count});
        try lib.format(writer, "\tRoot entry count: {}\n", .{bpb_2_0.root_entry_count});
        try lib.format(writer, "\tTotal sector count(16): {}\n", .{bpb_2_0.total_sector_count_16});
        try lib.format(writer, "\tMedia descriptor: {}\n", .{bpb_2_0.media_descriptor});
        try lib.format(writer, "\tFAT sector count (16): {}\n", .{bpb_2_0.fat_sector_count_16});

        const bpb_3_31 = mbr.bpb.dos3_31;
        try lib.format(writer, "\tPhysical sectors per track: {}\n", .{bpb_3_31.physical_sectors_per_track});
        try lib.format(writer, "\tDisk head count: {}\n", .{bpb_3_31.disk_head_count});
        try lib.format(writer, "\tHidden sector count: {}\n", .{bpb_3_31.hidden_sector_count});
        try lib.format(writer, "\tTotal sector count: {}\n", .{bpb_3_31.total_sector_count_32});

        const bpb_7_1_79 = mbr.bpb;

        try lib.format(writer, "\tFAT sector count (32): {}\n", .{bpb_7_1_79.fat_sector_count_32});
        try lib.format(writer, "\tDrive description: {}\n", .{bpb_7_1_79.drive_description});
        try lib.format(writer, "\tVersion: {}.{}\n", .{ bpb_7_1_79.version[0], bpb_7_1_79.version[1] });
        try lib.format(writer, "\tRoot directory cluster offset: {}\n", .{bpb_7_1_79.root_directory_cluster_offset});
        try lib.format(writer, "\tFS info sector: {}\n", .{bpb_7_1_79.fs_info_sector});
        try lib.format(writer, "\tBackup boot record sector: {}\n", .{bpb_7_1_79.backup_boot_record_sector});
        try lib.format(writer, "\tDrive number: {}\n", .{bpb_7_1_79.drive_number});
        try lib.format(writer, "\tExtended boot signature: {}\n", .{bpb_7_1_79.extended_boot_signature});
        try lib.format(writer, "\tSerial number: {}\n", .{bpb_7_1_79.serial_number});
        try lib.format(writer, "\tVolume label: {s}\n", .{bpb_7_1_79.volume_label});
        try lib.format(writer, "\tFilesystem type: {s}\n", .{bpb_7_1_79.filesystem_type});

        try lib.format(writer, "\nCode:\n", .{});
        for (mbr.code) |code_byte| {
            try lib.format(writer, "0x{x}, ", .{code_byte});
        }

        try lib.format(writer, "\n\nPartitions:\n", .{});
        for (mbr.partitions, 0..) |partition, partition_index| {
            if (partition.size_in_lba != 0) {
                try lib.format(writer, "[{}]\n", .{partition_index});
                try lib.format(writer, "\tBoot indicator: 0x{x}\n", .{partition.boot_indicator});
                try lib.format(writer, "\tStarting CHS: 0x{x}\n", .{partition.starting_chs});
                try lib.format(writer, "\tOS type: 0x{x}\n", .{partition.os_type});
                try lib.format(writer, "\tEnding CHS: 0x{x}\n", .{partition.ending_chs});
                try lib.format(writer, "\tFirst LBA: 0x{x}\n", .{partition.first_lba});
                try lib.format(writer, "\tSize in LBA: 0x{x}\n", .{partition.size_in_lba});
            }
        }
    }
};

pub const DAP = extern struct {
    size: u16 = 0x10,
    sector_count: u16,
    offset: u16,
    segment: u16,
    lba: u64,

    comptime {
        assert(@sizeOf(DAP) == 0x10);
    }
};
