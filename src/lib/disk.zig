const lib = @import("lib");

const FAT32 = lib.Filesystem.FAT32;
const GPT = lib.PartitionTable.GPT;
const MBR = lib.PartitionTable.MBR;

const ArrayListAligned = lib.ArrayListAligned;
const assert = lib.assert;
const asBytes = lib.asBytes;
const log = lib.log.scoped(.Disk);
const sliceAsBytes = lib.sliceAsBytes;

pub const Disk = extern struct {
    type: Type,
    disk_size: u64,
    partition_sizes: [GPT.default_max_partition_count]u64 = [1]u64{0} ** GPT.default_max_partition_count,
    cache_size: u16,
    sector_size: u16,
    callbacks: Callbacks,

    pub const Type = lib.DiskType;

    pub const ReadFn = fn (disk: *Disk, sector_count: u64, sector_offset: u64, provided_buffer: ?[]u8) ReadError!ReadResult;
    pub const ReadError = error{
        read_error,
    };
    pub const ReadResult = extern struct {
        sector_count: u64,
        buffer: [*]u8,
    };

    pub const ReadCacheFn = fn (disk: *Disk, sector_count: u64, sector_offset: u64) ReadError!ReadResult;

    pub const WriteFn = fn (disk: *Disk, bytes: []const u8, sector_offset: u64, commit_memory_to_disk: bool) WriteError!void;
    pub const WriteError = error{
        not_supported,
        disk_size_overflow,
    };

    pub const Callbacks = extern struct {
        read: *const ReadFn,
        write: *const WriteFn,
        readCache: *const ReadCacheFn,
    };

    pub inline fn getProvidedBuffer(disk: *Disk, comptime T: type, count: usize, allocator: ?*lib.Allocator, force: bool) !?[]u8 {
        if ((disk.type == .memory and force) or (disk.type != .memory)) {
            if (allocator) |alloc| {
                const size = @sizeOf(T) * count;
                const alignment = @alignOf(T);
                const result = try alloc.allocateBytes(size, alignment);
                const slice = @as([*]u8, @ptrFromInt(@as(usize, @intCast(result.address))))[0..@as(usize, @intCast(result.size))];
                if (slice.len != size) @panic("WTQSAD/jasD");
                return slice;
            }
        }

        return null;
    }

    const AdvancedReadOptions = packed struct(u8) {
        force: bool = false,
        reserved: u7 = 0,
    };

    pub fn readTypedSectors(disk: *Disk, comptime T: type, sector_offset: u64, allocator: ?*lib.Allocator, options: AdvancedReadOptions) !*T {
        const sector_count = @divExact(@sizeOf(T), disk.sector_size);
        const provided_buffer = try disk.getProvidedBuffer(T, 1, allocator, options.force);
        const read_result = try disk.callbacks.read(disk, sector_count, sector_offset, provided_buffer);
        if (read_result.sector_count != sector_count) @panic("Sector count mismatch");
        // Don't need to write back since it's a memory disk
        const result: *T = @ptrCast(@alignCast(read_result.buffer));
        return result;
    }

    pub inline fn writeTypedSectors(disk: *Disk, comptime T: type, content: *T, sector_offset: u64, commit_memory_to_disk: bool) !void {
        try disk.callbacks.write(disk, asBytes(content), sector_offset, commit_memory_to_disk);
    }

    pub inline fn readSlice(disk: *Disk, comptime T: type, len: usize, sector_offset: u64, allocator: ?*lib.Allocator, options: AdvancedReadOptions) ![]T {
        const element_count_per_sector = @divExact(disk.sector_size, @sizeOf(T));
        const sector_count = @divExact(len, element_count_per_sector);
        const provided_buffer = try disk.getProvidedBuffer(T, len, allocator, options.force);
        const read_result = try disk.callbacks.read(disk, sector_count, sector_offset, provided_buffer);
        if (read_result.sector_count != sector_count) @panic("read_slice: sector count mismatch");
        const result = @as([*]T, @ptrCast(@alignCast(read_result.buffer)))[0..len];
        return result;
    }

    pub inline fn writeSlice(disk: *Disk, comptime T: type, slice: []const T, sector_offset: u64, commit_memory_to_disk: bool) !void {
        const byte_slice = sliceAsBytes(slice);
        try disk.callbacks.write(disk, byte_slice, sector_offset, commit_memory_to_disk);
    }

    pub fn verify(disk: *Disk) !void {
        const mbr = try disk.read_typed_sectors(MBR.Struct, 0);
        try mbr.verify(disk);
        unreachable;
    }

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
            assert(@intFromEnum(Operation.read) == 0);
            assert(@intFromEnum(Operation.write) == 1);
        }
    };

    pub const PartitionRange = extern struct {
        first_lba: u64,
        last_lba: u64,
    };
};
