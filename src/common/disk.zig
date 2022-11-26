const Disk = @This();

const common = @import("../common.zig");
const FAT32 = common.Filesystem.FAT32;
const GPT = common.PartitionTable.GPT;
const MBR = common.PartitionTable.MBR;
const assert = common.assert;

pub const Type = enum(u32) {
    virtio = 0,
    nvme = 1,
    ahci = 2,
    ide = 3,
    memory = 4,
};

pub const Work = struct {
    sector_offset: u64,
    sector_count: u64,
    operation: Operation,
};

pub const Operation = enum(u1) {
    read = 0,
    write = 1,

    // This is used by NVMe and AHCI, so it is needed to match these values
    comptime {
        assert(@bitSizeOf(Operation) == @bitSizeOf(u1));
        assert(@enumToInt(Operation.read) == 0);
        assert(@enumToInt(Operation.write) == 1);
    }
};

pub const Descriptor = extern struct {
    type: Type,
    disk_size: u64 = 0,
    partition_sizes: [GPT.max_partition_count]u64 = [1]u64{0} ** GPT.max_partition_count,
    partition_count: u8,
    sector_size: u16 = 0x200,
    esp_index: u8,
    boot_partition_index: u8,
    callbacks: Callbacks,

    pub const ReadFn = fn (disk: *Disk.Descriptor, bytes: u64, offset: u64) ReadError![]u8;
    pub const ReadError = error{
        read_error,
    };
    pub const WriteFn = fn (disk: *Disk.Descriptor, bytes: []const u8, offset: u64) WriteError!void;
    pub const WriteError = error{
        write_error,
    };

    pub const Callbacks = extern struct {
        read: *const ReadFn,
        write: *const WriteFn,
    };

    const fat32_volumes_lba = GPT.reserved_partition_size / GPT.max_block_size / 2;

    pub fn image(disk: *Disk.Descriptor, partition_sizes: []const u64, maybe_mbr: ?[]const u8, esp_index: u8, boot_partition_index: u8, callbacks: Callbacks) !void {
        if (partition_sizes.len > GPT.max_partition_count) return VerifyError.partition_count_too_big;

        disk.* = Disk.Descriptor{
            .type = .memory,
            .partition_count = @intCast(u8, partition_sizes.len),
            .esp_index = esp_index,
            .boot_partition_index = boot_partition_index,
            .callbacks = callbacks,
        };

        for (disk.partition_sizes[0..disk.partition_count]) |*partition_size, partition_index| {
            const provided_partition_size = partition_sizes[partition_index];
            partition_size.* = provided_partition_size;
        }

        for (disk.partition_sizes[disk.partition_count..]) |*partition_size| {
            partition_size.* = 0;
        }

        try disk.verify();

        if (maybe_mbr) |provided_mbr| {
            // MBR
            try disk.callbacks.write(disk, provided_mbr, 0);
            const mbr_bytes = try disk.callbacks.read(disk, 0x200, 0);
            // Don't need to write back since it's a memory disk
            const mbr = @ptrCast(*MBR.Struct, @alignCast(@alignOf(MBR.Struct), mbr_bytes.ptr));
            const disk_last_lba = disk.get_disk_last_lba();
            mbr.partitions[0] = MBR.Partition{
                .boot_indicator = 0,
                .starting_chs = 0x200,
                .os_type = 0xee,
                .ending_chs = 0xff_ff_ff,
                .first_lba = 1,
                .size_in_lba = @intCast(u32, disk_last_lba + 1),
            };

            // GPT
            // 1. Write partition array
            const backup_gpt_lba_count = disk.get_backup_gpt_lba_count();
            const first_usable_lba = disk.get_gpt_lba_count();
            const last_usable_lba = disk_last_lba - backup_gpt_lba_count;

            var next_lba: u64 = fat32_volumes_lba;
            var gpt_partition_bytes = try disk.callbacks.read(disk, @sizeOf(GPT.Partition) * GPT.max_partition_count, GPT.partition_array_lba_start);
            const used_gpt_partitions = @ptrCast([*]GPT.Partition, @alignCast(@alignOf(GPT.Partition), gpt_partition_bytes))[0..disk.partition_count];

            for (used_gpt_partitions) |*partition, partition_index| {
                const is_esp = partition_index == disk.esp_index;
                const boot_flag: u8 = @boolToInt(partition_index == disk.boot_partition_index);
                const last_lba = get_block_last_lba(next_lba, disk.partition_sizes[partition_index], disk.sector_size);
                partition.* = GPT.Partition{
                    .partition_type_guid = if (is_esp) GPT.efi_system_partition_guid else GPT.microsoft_basic_data_partition_guid,
                    .unique_partition_guid = GPT.GUID.get_random(),
                    .first_lba = next_lba,
                    .last_lba = last_lba,
                    .attribute_flags = [_]u8{ 0, 0, 0, 0, 0, 0, 0, boot_flag },
                    .partition_name = [_]u16{ 'P', 'a', 'r', 't', 'i', 't', 'i', 'o', 'n', ' ', if (partition_index >= 100) 0x30 + @intCast(u16, partition_index) / 100 else ' ', if (partition_index >= 10) 0x30 + @intCast(u16, partition_index) / 10 else ' ', 0x30 + @intCast(u16, partition_index) } ++ ([1]u16{0} ** 23),
                };
            }

            const unused_gpt_partitions = @ptrCast([*]GPT.Partition, @alignCast(@alignOf(GPT.Partition), gpt_partition_bytes))[disk.partition_count..GPT.max_partition_count];
            for (unused_gpt_partitions) |*partition| {
                partition.* = common.zeroes(GPT.Partition);
            }

            const partition_entry_array_crc32 = common.CRC32.compute(gpt_partition_bytes);

            // 2. Write GPT headers
            const gpt_header_bytes = try disk.callbacks.read(disk, @sizeOf(GPT.Header), GPT.header_lba);
            const gpt_header = @ptrCast(*GPT.Header, @alignCast(@alignOf(GPT.Header), gpt_header_bytes));
            gpt_header.* = GPT.Header{
                .current_lba = GPT.header_lba,
                .backup_lba = disk_last_lba,
                .first_usable_lba = first_usable_lba,
                .last_usable_lba = last_usable_lba,
                .disk_guid = GPT.GUID.get_random(),
                .partition_entry_array_crc32 = partition_entry_array_crc32,
            };
            gpt_header.header_crc32 = common.CRC32.compute(gpt_header_bytes);

            common.std.debug.print("Backup LBA: {}. Backup offset: {}. Disk len: {}\n", .{ gpt_header.backup_lba, gpt_header.backup_lba * disk.sector_size, disk.disk_size });

            const backup_gpt_partition_bytes = try disk.callbacks.read(disk, @sizeOf(GPT.Partition) * GPT.max_partition_count, backup_gpt_lba_count);
            common.copy(u8, backup_gpt_partition_bytes, gpt_partition_bytes);

            const backup_gpt_header_bytes = try disk.callbacks.read(disk, @sizeOf(GPT.Header), gpt_header.backup_lba);
            const backup_gpt_header = @ptrCast(*GPT.Header, @alignCast(@alignOf(GPT.Header), backup_gpt_header_bytes));
            backup_gpt_header.* = gpt_header.*;

            backup_gpt_header.header_crc32 = 0;
            backup_gpt_header.current_lba = gpt_header.backup_lba;
            backup_gpt_header.backup_lba = gpt_header.current_lba;
            backup_gpt_header.partition_entry_array_starting_lba = gpt_header.last_usable_lba + 1;
            backup_gpt_header.header_crc32 = common.CRC32.compute(backup_gpt_header_bytes);

            // 3. Write FAT32 volumes
            unreachable;
        } else {
            unreachable;
        }

        @panic("todo image");
    }

    fn get_block_last_lba(offset: u64, size: u64, sector_size: u64) u64 {
        return offset + (size / sector_size) - 1;
    }

    fn get_gpt_lba_count(disk: *Disk.Descriptor) u8 {
        return @intCast(u8, GPT.partition_array_size / disk.sector_size + 2);
    }

    fn get_disk_last_lba(disk: *Disk.Descriptor) u64 {
        return disk.disk_size / disk.sector_size - 1;
    }

    fn get_backup_gpt_lba_count(disk: *Disk.Descriptor) u8 {
        return disk.get_gpt_lba_count() - 1;
    }

    const VerifyError = error{
        no_partitions,
        partition_count_too_big,
        invalid_esp_partition_index,
        partition_size_too_small,
        invalid_disk_size,
        partition_size_too_big,
        disk_size_too_small,
        disk_size_too_big,
    };

    pub fn get_required_disk_size(disk: Disk.Descriptor) !u64 {
        var size: u64 = GPT.reserved_partition_size;

        for (disk.partition_sizes[0..disk.partition_count]) |partition_size| {
            if (partition_size < FAT32.minimum_partition_size) return VerifyError.partition_size_too_small;
            if (partition_size > FAT32.maximum_partition_size) return VerifyError.partition_size_too_big;
            size += partition_size;
            common.std.debug.print("Disk size: {}. Partition size: {}\n", .{ size, partition_size });
        }

        return size;
    }

    pub fn verify(disk: *Disk.Descriptor) !void {
        if (disk.partition_sizes.len == 0) return VerifyError.no_partitions;
        if (disk.esp_index >= disk.partition_sizes.len) return VerifyError.invalid_esp_partition_index;
        disk.disk_size = try disk.get_required_disk_size();
        if (disk.disk_size < Disk.Descriptor.min_size) return VerifyError.disk_size_too_small;
        if (disk.disk_size > Disk.Descriptor.max_size) return VerifyError.disk_size_too_big;
    }

    pub const min_partition_size = FAT32.minimum_partition_size;
    pub const min_size = FAT32.minimum_partition_size + GPT.reserved_partition_size;
    pub const max_size = GPT.max_partition_count * FAT32.maximum_partition_size + GPT.reserved_partition_size;
};
