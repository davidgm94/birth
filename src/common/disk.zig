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
    disk_size: u64,
    partition_sizes: [GPT.max_partition_count]u64 = [1]u64{0} ** GPT.max_partition_count,
    sector_size: u16 = 0x200,
    partition_count: u8 = 0,
    callbacks: Callbacks,

    pub const ReadFn = fn (disk: *Disk.Descriptor, sector_count: u64, sector_offset: u64) ReadError![]u8;
    pub const ReadError = error{
        read_error,
    };
    pub const WriteFn = fn (disk: *Disk.Descriptor, bytes: []const u8, offset: u64, options: WriteOptions) WriteError!void;
    pub const WriteError = error{
        write_error,
    };

    pub const Callbacks = extern struct {
        read: *const ReadFn,
        write: *const WriteFn,
    };

    pub const WriteOptions = packed struct(u64) {
        in_memory_writings: bool = false,
        reserved: u63 = 0,

        pub fn forced_write(write_options: WriteOptions) WriteOptions {
            var new_options = write_options;
            new_options.in_memory_writings = false;
            return new_options;
        }
    };

    pub inline fn read_typed_sectors(disk: *Disk.Descriptor, comptime T: type, sector_offset: u64) !*T {
        const bytes = try disk.callbacks.read(disk, @divExact(@sizeOf(T), disk.sector_size), sector_offset);
        // Don't need to write back since it's a memory disk
        const result = @ptrCast(*T, @alignCast(@alignOf(T), bytes.ptr));
        return result;
    }

    pub inline fn write_typed_sectors(disk: *Disk.Descriptor, comptime T: type, content: *T, sector_offset: u64, write_options: WriteOptions) !void {
        try disk.callbacks.write(disk, common.as_bytes(content), sector_offset, write_options);
    }

    pub inline fn read_slice(disk: *Disk.Descriptor, comptime T: type, len: usize, sector_offset: u64) ![]T {
        const element_count_per_sector = @divExact(disk.sector_size, @sizeOf(T));
        const sector_count = @divExact(len, element_count_per_sector);
        const bytes = try disk.callbacks.read(disk, sector_count, sector_offset);
        const result = @ptrCast([*]T, @alignCast(@alignOf(T), bytes.ptr))[0..len];
        return result;
    }

    pub inline fn write_slice(disk: *Disk.Descriptor, comptime T: type, slice: []const T, sector_offset: u64, write_options: WriteOptions) !void {
        try disk.callbacks.write(disk, common.slice_as_bytes(slice), sector_offset, write_options);
    }

    pub fn verify(disk: *Disk.Descriptor) !void {
        const mbr = try disk.read_typed_sectors(MBR.Struct, 0);
        try mbr.verify(disk);
        unreachable;
    }
};
