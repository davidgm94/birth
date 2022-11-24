const Disk = @This();

const common = @import("../common.zig");
const FAT32 = common.Filesystem.FAT32;
const GPT = common.PartitionTable.GPT;
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

    pub fn image(disk: *Disk.Descriptor, partition_sizes: []const u64, maybe_mbr: ?[]const u8, esp_index: u8, callbacks: Callbacks) !void {
        if (partition_sizes.len > GPT.max_partition_count) return VerifyError.partition_count_too_big;

        disk.* = Disk.Descriptor{
            .type = .memory,
            .esp_index = esp_index,
            .partition_count = @intCast(u8, partition_sizes.len),
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
            try disk.callbacks.write(disk, provided_mbr, 0);
            const mbr = try disk.callbacks.read(disk, 0x200, 0);
            _ = mbr;
            unreachable;
        } else {
            unreachable;
        }
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
        }

        return size;
    }

    pub fn verify(disk: *Disk.Descriptor) !void {
        if (disk.partition_sizes.len == 0) return VerifyError.no_partitions;
        if (disk.esp_index >= disk.partition_sizes.len) return VerifyError.invalid_esp_partition_index;
        const disk_size = try disk.get_required_disk_size();
        if (disk_size < Disk.Descriptor.min_size) return VerifyError.disk_size_too_small;
        if (disk_size > Disk.Descriptor.max_size) return VerifyError.disk_size_too_big;
    }

    pub const min_size = FAT32.minimum_partition_size + GPT.reserved_partition_size;
    pub const max_size = GPT.max_partition_count * FAT32.maximum_partition_size + GPT.reserved_partition_size;
};
