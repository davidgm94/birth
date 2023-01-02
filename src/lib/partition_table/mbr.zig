const MBR = @This();

const lib = @import("../../lib.zig");
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
        assert(@sizeOf(@This()) == 0x200);
    }

    pub fn compare(mbr: *Partition, other: *MBR.Partition) void {
        log.debug("Comparing MBRs...", .{});
        mbr.bpb.compare(&other.bpb);

        if (!lib.equal(u8, &mbr.code, &other.code)) {
            unreachable;
        }

        for (mbr.partitions) |this_partition, partition_i| {
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
        if (!lib.equal(u8, &filesystem_type, "FAT32   ")) {
            return VerificationError.filesystem_type;
        }

        unreachable;
    }

    pub fn format(mbr: *const MBR.Partition, comptime _: []const u8, _: lib.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try lib.internal_format(writer, "MBR:\n", .{});
        const bpb_2_0 = mbr.bpb.dos3_31.dos2_0;
        try lib.internal_format(writer, "\tJump code: [0x{x}, 0x{x}, 0x{x}]\n", .{ bpb_2_0.jmp_code[0], bpb_2_0.jmp_code[1], bpb_2_0.jmp_code[2] });
        try lib.internal_format(writer, "\tOEM identifier: {s}\n", .{bpb_2_0.oem_identifier});
        try lib.internal_format(writer, "\tSector size: {}\n", .{bpb_2_0.sector_size});
        try lib.internal_format(writer, "\tCluster sector count: {}\n", .{bpb_2_0.cluster_sector_count});
        try lib.internal_format(writer, "\tReserved sector count: {}\n", .{bpb_2_0.reserved_sector_count});
        try lib.internal_format(writer, "\tFAT count: {}\n", .{bpb_2_0.fat_count});
        try lib.internal_format(writer, "\tRoot entry count: {}\n", .{bpb_2_0.root_entry_count});
        try lib.internal_format(writer, "\tTotal sector count(16): {}\n", .{bpb_2_0.total_sector_count_16});
        try lib.internal_format(writer, "\tMedia descriptor: {}\n", .{bpb_2_0.media_descriptor});
        try lib.internal_format(writer, "\tFAT sector count (16): {}\n", .{bpb_2_0.fat_sector_count_16});

        const bpb_3_31 = mbr.bpb.dos3_31;
        try lib.internal_format(writer, "\tPhysical sectors per track: {}\n", .{bpb_3_31.physical_sectors_per_track});
        try lib.internal_format(writer, "\tDisk head count: {}\n", .{bpb_3_31.disk_head_count});
        try lib.internal_format(writer, "\tHidden sector count: {}\n", .{bpb_3_31.hidden_sector_count});
        try lib.internal_format(writer, "\tTotal sector count: {}\n", .{bpb_3_31.total_sector_count_32});

        const bpb_7_1_79 = mbr.bpb;

        try lib.internal_format(writer, "\tFAT sector count (32): {}\n", .{bpb_7_1_79.fat_sector_count_32});
        try lib.internal_format(writer, "\tDrive description: {}\n", .{bpb_7_1_79.drive_description});
        try lib.internal_format(writer, "\tVersion: {}.{}\n", .{ bpb_7_1_79.version[0], bpb_7_1_79.version[1] });
        try lib.internal_format(writer, "\tRoot directory cluster offset: {}\n", .{bpb_7_1_79.root_directory_cluster_offset});
        try lib.internal_format(writer, "\tFS info sector: {}\n", .{bpb_7_1_79.fs_info_sector});
        try lib.internal_format(writer, "\tBackup boot record sector: {}\n", .{bpb_7_1_79.backup_boot_record_sector});
        try lib.internal_format(writer, "\tDrive number: {}\n", .{bpb_7_1_79.drive_number});
        try lib.internal_format(writer, "\tExtended boot signature: {}\n", .{bpb_7_1_79.extended_boot_signature});
        try lib.internal_format(writer, "\tSerial number: {}\n", .{bpb_7_1_79.serial_number});
        try lib.internal_format(writer, "\tVolume label: {s}\n", .{bpb_7_1_79.volume_label});
        try lib.internal_format(writer, "\tFilesystem type: {s}\n", .{bpb_7_1_79.filesystem_type});

        try lib.internal_format(writer, "\nCode:\n", .{});
        for (mbr.code) |code_byte| {
            try lib.internal_format(writer, "0x{x}, ", .{code_byte});
        }

        try lib.internal_format(writer, "\n\nPartitions:\n", .{});
        for (mbr.partitions) |partition, partition_index| {
            if (partition.size_in_lba != 0) {
                try lib.internal_format(writer, "[{}]\n", .{partition_index});
                try lib.internal_format(writer, "\tBoot indicator: 0x{x}\n", .{partition.boot_indicator});
                try lib.internal_format(writer, "\tStarting CHS: 0x{x}\n", .{partition.starting_chs});
                try lib.internal_format(writer, "\tOS type: 0x{x}\n", .{partition.os_type});
                try lib.internal_format(writer, "\tEnding CHS: 0x{x}\n", .{partition.ending_chs});
                try lib.internal_format(writer, "\tFirst LBA: 0x{x}\n", .{partition.first_lba});
                try lib.internal_format(writer, "\tSize in LBA: 0x{x}\n", .{partition.size_in_lba});
            }
        }
    }
};

pub const DAP = extern struct {
    size: u8 = 0x10,
    unused: u8 = 0,
    sector_count: u16,
    pointer: u32,
    lba: u64,

    comptime {
        assert(@sizeOf(DAP) == 0x10);
    }
};

pub const BootDisk = extern struct {
    bpb: BIOSParameterBlock.DOS7_1_79,
    code: [code_byte_count]u8,
    gdt_32: GDT32,
    dap: DAP align(2),
    partitions: [4]LegacyPartition align(2),
    signature: [2]u8 = [_]u8{ 0x55, 0xaa },

    const GDT32 = extern struct {
        register: Register,
        code_32: Descriptor = .{
            .access = 0b10011010,
            .granularity = 0b11001111,
        },
        data_32: Descriptor = .{
            .access = 0b10010010,
            .granularity = 0b11001111,
        },

        comptime {
            assert(@sizeOf(GDT32) == @sizeOf(Register) + 2 * @sizeOf(Descriptor));
        }

        const Descriptor = extern struct {
            limit: u16 = 0xffff,
            base_low: u16 = 0,
            base_mid: u8 = 0,
            access: u8,
            granularity: u8,
            base_high: u8 = 0,

            comptime {
                assert(@sizeOf(Descriptor) == @sizeOf(u64));
            }
        };

        const Register = extern struct {
            size: u16,
            pointer: u32 align(2),

            comptime {
                assert(@sizeOf(Register) == @sizeOf(u16) + @sizeOf(u32));
            }
        };
    };

    const code_byte_count = 0x13e;
    const offset: u16 = 0x7c00;

    const hlt = [_]u8{0xf4};
    const clc = [_]u8{0xf8};
    const cli = [_]u8{0xfa};
    const sti = [_]u8{0xfb};
    const cld = [_]u8{0xfc};

    const xor = 0x31;
    const xor_si_si_16 = [_]u8{ xor, 0xf6 };
    const mov_ds_si = [_]u8{ 0x8e, 0xde };
    const mov_es_si = [_]u8{ 0x8e, 0xc6 };
    const mov_ss_si = [_]u8{ 0x8e, 0xd6 };
    const mov_sp_0x7c00 = [_]u8{ 0xbc, 0x00, 0x7c };
    const mov_bx_0xaa55 = [_]u8{ 0xbb, 0xaa, 0x55 };
    const cmp_bx_0xaa55 = [_]u8{ 0x81, 0xfb, 0x55, 0xaa };

    const jc = 0x72;
    const jne = 0x75;

    const mov_eax_cr0 = [_]u8{ 0x0f, 0x20, 0xc0 };
    const mov_cr0_eax = [_]u8{ 0x0f, 0x22, 0xc0 };
    const reload_data_segments_32 = [_]u8{
        0xb8, 0x10, 0x00, 0x00, 0x00, // mov eax, 0x10
        0x8e, 0xd8, // mov ds, ax
        0x8e, 0xc0, // mov es, ax
        0x8e, 0xe0, // mov fs, ax
        0x8e, 0xe8, // mov gs, ax
        0x8e, 0xd0, // mov ss, ax
    };
    const xor_eax_eax = [_]u8{ xor, 0xc8 };
    const xor_ebx_ebx = [_]u8{ xor, 0xdb };
    const nop = [_]u8{0x90};

    fn or_ax(imm8: u8) [4]u8 {
        return .{ 0x66, 0x83, 0xc8, imm8 };
    }

    fn int(interrupt_number: u8) [2]u8 {
        return .{ 0xcd, interrupt_number };
    }

    fn mov_si(imm16: u16) [3]u8 {
        const imm_bytes = lib.asBytes(&imm16);
        return .{ 0xbe, imm_bytes[0], imm_bytes[1] };
    }

    fn mov_ah(imm8: u8) [2]u8 {
        return .{ 0xb4, imm8 };
    }

    pub fn fill(mbr: *BootDisk, allocator: lib.Allocator, dap: DAP) !void {
        // Hardcoded jmp to end of FAT32 BPB
        const jmp_to_end_of_bpb = .{ 0xeb, @sizeOf(BIOSParameterBlock.DOS7_1_79) - 2 };
        mbr.bpb.dos3_31.dos2_0.jmp_code = jmp_to_end_of_bpb ++ nop;
        mbr.dap = dap;
        mbr.gdt_32 = GDT32{
            .register = .{
                .size = @sizeOf(GDT32) - @sizeOf(GDT32.Register) + 8 - 1,
                .pointer = offset + @offsetOf(BootDisk, "gdt_32") + @offsetOf(GDT32, "code_32") - 8,
            },
        };
        log.debug("GDT: {}", .{mbr.gdt_32});
        var assembler = Assembler{
            .boot_disk = mbr,
            .patches = lib.ArrayListManaged(Patch).init(allocator),
            .labels = lib.ArrayListManaged(Label.Offset).init(allocator),
        };
        defer assembler.patch();

        assembler.add_instruction(&cli);
        assembler.add_instruction(&cld);
        try assembler.far_jmp_16(0x0, .reload_cs_16);

        try assembler.add_instruction_with_label(&xor_si_si_16, .reload_cs_16);
        assembler.add_instruction(&mov_ds_si);
        assembler.add_instruction(&mov_es_si);
        assembler.add_instruction(&mov_ss_si);
        assembler.add_instruction(&mov_sp_0x7c00);
        assembler.add_instruction(&sti);
        assembler.add_instruction(&mov_ah(0x41));
        assembler.add_instruction(&mov_bx_0xaa55);
        assembler.add_instruction(&int(0x13));
        try assembler.jcc(jc, .error16);
        assembler.add_instruction(&cmp_bx_0xaa55);
        try assembler.jcc(jne, .error16);
        try assembler.add_instruction_with_label(&mov_ah(0x42), .read_sectors);
        try assembler.mov_si(.dap);
        assembler.add_instruction(&clc);
        assembler.add_instruction(&int(0x13));
        try assembler.jcc(jc, .error16);
        try assembler.lgdt_16(.gdt);
        assembler.add_instruction(&cli);
        assembler.add_instruction(&mov_eax_cr0);
        assembler.add_instruction(&or_ax(1));
        assembler.add_instruction(&mov_cr0_eax);
        try assembler.far_jmp_16(0x8, .protected_mode);

        try assembler.add_instruction_with_label(&cli, .error16);
        assembler.add_instruction(&hlt);

        // TODO: unwrap byte chunk
        try assembler.add_instruction_with_label(&reload_data_segments_32, .protected_mode);
        assembler.add_instruction(&xor_eax_eax);
        assembler.add_instruction(&xor_ebx_ebx);
        // 8b 2d ac 7d 00 00    	mov    ebp,DWORD PTR [rip+0x7dac]        # 0x7e5c
        try assembler.mov_ebp_dword_ptr(.dap_pointer);
        //b0:	66 8b 5d 2a          	mov    bx,WORD PTR [rbp+0x2a]
        assembler.add_instruction(&.{ 0x66, 0x8b, 0x5d, 0x2a });
        //b4:	66 8b 45 2c          	mov    ax,WORD PTR [rbp+0x2c]
        assembler.add_instruction(&.{ 0x66, 0x8b, 0x45, 0x2c });
        //b8:	8b 55 1c             	mov    edx,DWORD PTR [rbp+0x1c]
        assembler.add_instruction(&.{ 0x8b, 0x55, 0x1c });
        //bb:	01 ea                	add    edx,ebp
        assembler.add_instruction(&.{ 0x01, 0xea });
        //bd:	83 3a 01             	cmp    DWORD PTR [rdx],0x1
        try assembler.add_instruction_with_label(&.{ 0x83, 0x3a, 0x01 }, .elf_loader_loop);
        //c0:	75 0d                	jne    0xcf
        try assembler.jcc(jne, .elf_loader_loop_continue);
        //c2:	89 ee                	mov    esi,ebp
        assembler.add_instruction(&.{ 0x89, 0xee });
        //c4:	03 72 04             	add    esi,DWORD PTR [rdx+0x4]
        assembler.add_instruction(&.{ 0x03, 0x72, 0x04 });
        //c7:	8b 7a 0c             	mov    edi,DWORD PTR [rdx+0xc]
        assembler.add_instruction(&.{ 0x8b, 0x7a, 0x0c });
        //ca:	8b 4a 10             	mov    ecx,DWORD PTR [rdx+0x10]
        assembler.add_instruction(&.{ 0x8b, 0x4a, 0x10 });
        //cd:	f3 a4                	rep movs BYTE PTR es:[rdi],BYTE PTR ds:[rsi]
        assembler.add_instruction(&.{ 0xf3, 0xa4 });
        //cf:	01 da                	add    edx,ebx
        try assembler.add_instruction_with_label(&.{ 0x01, 0xda }, .elf_loader_loop_continue);
        //d1:	48                      dec    eax
        assembler.add_instruction(&.{0x48});
        // jnz loop
        const jnz = jne;
        try assembler.jcc(jnz, .elf_loader_loop);
        //d5:	8b 5d 18             	mov    ebx,DWORD PTR [rbp+0x18]
        assembler.add_instruction(&.{ 0x8b, 0x5d, 0x18 });
        //d8:	ff e3                	jmp    rbx
        assembler.add_instruction(&.{ 0xff, 0xe3 });
    }

    const Label = enum {
        reload_cs_16,
        error16,
        read_sectors,
        dap,
        dap_pointer,
        gdt,
        protected_mode,
        elf_loader_loop,
        elf_loader_loop_continue,

        const Offset = struct {
            label: Label,
            offset: u8,
        };
    };

    const Patch = struct {
        label: Label,
        label_size: u8,
        label_offset: u8,
        // For relative labels, instruction len to compute RIP-relative address
        // For absolute labels, offset in which to introduce a 8-bit absolute offset
        label_type: enum {
            relative,
            absolute,
        },
        label_section: enum {
            code,
            data,
        },
        instruction_starting_offset: u8,
        instruction_len: u8,
    };

    pub const Assembler = struct {
        boot_disk: *BootDisk,
        code_index: u8 = 0,
        patches: lib.ArrayListManaged(Patch),
        labels: lib.ArrayListManaged(Label.Offset),

        pub inline fn add_instruction(assembler: *Assembler, instruction_bytes: []const u8) void {
            assert(assembler.code_index + instruction_bytes.len <= assembler.boot_disk.code.len);
            lib.print("[0x{x:0>4}] ", .{offset + @offsetOf(BootDisk, "code") + assembler.code_index});
            for (instruction_bytes) |byte| {
                lib.print("{x:0>2} ", .{byte});
            }
            lib.print("\n", .{});
            lib.copy(u8, assembler.boot_disk.code[assembler.code_index .. assembler.code_index + instruction_bytes.len], instruction_bytes);
            assembler.code_index += @intCast(u8, instruction_bytes.len);
        }

        pub fn add_instruction_with_label(assembler: *Assembler, instruction_bytes: []const u8, label: Label) !void {
            try assembler.labels.append(.{ .label = label, .offset = assembler.code_index });
            assembler.add_instruction(instruction_bytes);
        }

        pub fn far_jmp_16(assembler: *Assembler, segment: u16, label: Label) !void {
            const segment_bytes = lib.asBytes(&segment);
            const offset_bytes = lib.asBytes(&offset);
            const instruction_bytes = [_]u8{ 0xea, offset_bytes[0], offset_bytes[1], segment_bytes[0], segment_bytes[1] };
            try assembler.patches.append(.{
                .label = label,
                .label_size = @sizeOf(u16),
                .label_offset = 1,
                .label_type = .absolute,
                .label_section = .code,
                .instruction_starting_offset = assembler.code_index,
                .instruction_len = instruction_bytes.len,
            });
            assembler.add_instruction(&instruction_bytes);
        }

        pub fn jcc(assembler: *Assembler, jmp_opcode: u8, label: Label) !void {
            const instruction_bytes = [_]u8{ jmp_opcode, 0x00 };
            try assembler.patches.append(.{
                .label = label,
                .label_size = @sizeOf(u8),
                .label_offset = 1,
                .label_type = .relative,
                .label_section = .code,
                .instruction_starting_offset = assembler.code_index,
                .instruction_len = instruction_bytes.len,
            });
            assembler.add_instruction(&instruction_bytes);
        }

        pub fn mov_si(assembler: *Assembler, label: Label) !void {
            const instruction_bytes = [_]u8{ 0xbe, 0x00, 0x00 };
            try assembler.patches.append(.{
                .label = label,
                .label_size = @sizeOf(u16),
                .label_offset = 1,
                .label_type = .absolute,
                .label_section = .data,
                .instruction_starting_offset = assembler.code_index,
                .instruction_len = instruction_bytes.len,
            });
            assembler.add_instruction(&instruction_bytes);
        }

        pub fn lgdt_16(assembler: *Assembler, label: Label) !void {
            const instruction_bytes = [_]u8{ 0x0f, 0x01, 0x16, 0x00, 0x00 };
            try assembler.patches.append(.{
                .label = label,
                .label_size = @sizeOf(u16),
                .label_offset = 3,
                .label_type = .absolute,
                .label_section = .data,
                .instruction_starting_offset = assembler.code_index,
                .instruction_len = instruction_bytes.len,
            });
            assembler.add_instruction(&instruction_bytes);
        }

        pub fn mov_ebp_dword_ptr(assembler: *Assembler, label: Label) !void {
            const instruction_bytes = [_]u8{ 0x8b, 0x2d, 0x00, 0x00, 0x00, 0x00 };
            try assembler.patches.append(.{
                .label = label,
                .label_size = @sizeOf(u16),
                .label_offset = 2,
                .label_type = .absolute,
                .label_section = .data,
                .instruction_starting_offset = assembler.code_index,
                .instruction_len = instruction_bytes.len,
            });
            assembler.add_instruction(&instruction_bytes);
        }

        pub fn patch(assembler: *Assembler) void {
            var patched: usize = 0;

            next_patch: for (assembler.patches.items) |patch_descriptor| {
                const index = patch_descriptor.instruction_starting_offset + patch_descriptor.label_offset;
                log.debug("Trying to patch instruction. Section: {s}. Label: {s}. Label size: {}. Label type: {s}", .{ @tagName(patch_descriptor.label_section), @tagName(patch_descriptor.label), patch_descriptor.label_size, @tagName(patch_descriptor.label_type) });
                switch (patch_descriptor.label_section) {
                    .code => for (assembler.labels.items) |label_descriptor| {
                        if (patch_descriptor.label == label_descriptor.label) {
                            switch (patch_descriptor.label_type) {
                                .absolute => {
                                    assert(patch_descriptor.label_size == @sizeOf(u16));
                                    @ptrCast(*align(1) u16, &assembler.boot_disk.code[index]).* = offset + @offsetOf(BootDisk, "code") + label_descriptor.offset;
                                },
                                .relative => {
                                    assert(patch_descriptor.label_size == @sizeOf(u8));
                                    assert(patch_descriptor.label_section == .code);
                                    const computed_after_instruction_offset = patch_descriptor.instruction_starting_offset + patch_descriptor.instruction_len;
                                    const operand_a = @intCast(isize, label_descriptor.offset);
                                    const operand_b = @intCast(isize, computed_after_instruction_offset);
                                    const diff = @bitCast(u8, @intCast(i8, operand_a - operand_b));
                                    log.debug("Operand A: 0x{x}. Operand B: 0x{x}. Result: 0x{x}", .{ operand_a, operand_b, diff });
                                    @ptrCast(*align(1) u8, &assembler.boot_disk.code[index]).* = diff;
                                },
                            }

                            const instruction_start = offset + @offsetOf(BootDisk, "code") + patch_descriptor.instruction_starting_offset;
                            lib.print("[0x{x:0>4}] ", .{instruction_start});
                            const instruction_bytes = assembler.boot_disk.code[patch_descriptor.instruction_starting_offset .. patch_descriptor.instruction_starting_offset + patch_descriptor.instruction_len];
                            for (instruction_bytes) |byte| {
                                lib.print("{x:0>2} ", .{byte});
                            }
                            lib.print("\n", .{});
                            patched += 1;
                            continue :next_patch;
                        }
                    },
                    .data => {
                        log.debug("Data: {s}", .{@tagName(patch_descriptor.label)});
                        const dap_offset = @offsetOf(BootDisk, "dap");
                        log.debug("DAP offset: 0x{x}", .{dap_offset});
                        switch (patch_descriptor.label_type) {
                            .absolute => {
                                assert(patch_descriptor.label_size == @sizeOf(u16));
                                @ptrCast(*align(1) u16, &assembler.boot_disk.code[index]).* = offset + @as(u16, switch (patch_descriptor.label) {
                                    .dap => dap_offset,
                                    .gdt => @offsetOf(BootDisk, "gdt_32"),
                                    .dap_pointer => dap_offset + @offsetOf(DAP, "pointer"),
                                    else => unreachable,
                                });
                            },
                            .relative => unreachable,
                            //assert(patch_descriptor.label_size == @sizeOf(u32));
                            //const relative_offset: u32 = switch (patch_descriptor.label) {
                            //else => unreachable,
                            //};
                            //log.debug("DAP pointer offset: 0x{x}", .{relative_offset});
                            //log.debug("Total offset: 0x{x}", .{relative_offset + offset});
                            //const computed_after_instruction_offset = @offsetOf(BootDisk, "code") + patch_descriptor.instruction_starting_offset + patch_descriptor.instruction_len;
                            //assert(relative_offset >= computed_after_instruction_offset);
                            //const diff = relative_offset - computed_after_instruction_offset;
                            //const offset_to_write = offset + diff;
                            //log.debug("offset to write: 0x{x}", .{offset_to_write});
                            //log.debug("label size: {}", .{patch_descriptor.label_size});
                            //@ptrCast(*align(1) u32, &assembler.boot_disk.code[index]).* = offset_to_write;
                            //},
                        }

                        log.debug("Patched instruction:", .{});
                        const instruction_start = offset + @offsetOf(BootDisk, "code") + patch_descriptor.instruction_starting_offset;
                        lib.print("[0x{x:0>4}] ", .{instruction_start});
                        const instruction_bytes = assembler.boot_disk.code[patch_descriptor.instruction_starting_offset .. patch_descriptor.instruction_starting_offset + patch_descriptor.instruction_len];
                        for (instruction_bytes) |byte| {
                            lib.print("{x:0>2} ", .{byte});
                        }
                        lib.print("\n", .{});

                        patched += 1;
                        continue :next_patch;
                    },
                }

                log.debug("Patch count: {}. Patched count: {}", .{ assembler.patches.items.len, patched });
                assert(patched == assembler.patches.items.len);
            }
        }
    };

    comptime {
        assert(@sizeOf(@This()) == 0x200);
    }
};
