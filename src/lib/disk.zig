const host = @import("../host.zig");

const lib = @import("../lib.zig");
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
    sector_size: u16,
    callbacks: Callbacks,

    pub const Type = lib.DiskType;

    pub const ReadFn = fn (disk: *Disk, sector_count: u64, sector_offset: u64, provided_buffer: ?[]const u8) ReadError!ReadResult;
    pub const ReadError = error{
        read_error,
    };
    pub const ReadResult = extern struct {
        sector_count: u64,
        buffer: [*]u8,
    };
    pub const WriteFn = fn (disk: *Disk, bytes: []const u8, sector_offset: u64, commit_memory_to_disk: bool) WriteError!void;
    pub const WriteError = error{
        write_error,
    };

    pub const Callbacks = extern struct {
        read: *const ReadFn,
        write: *const WriteFn,
    };

    pub inline fn read_typed_sectors(disk: *Disk, comptime T: type, sector_offset: u64, provided_buffer: ?[]const u8) !*T {
        const sector_count = @divExact(@sizeOf(T), disk.sector_size);
        const read_result = try disk.callbacks.read(disk, sector_count, sector_offset, provided_buffer);
        if (read_result.sector_count != sector_count) @panic("WTF");
        // Don't need to write back since it's a memory disk
        const result = @ptrCast(*T, @alignCast(@alignOf(T), read_result.buffer));
        return result;
    }

    pub inline fn write_typed_sectors(disk: *Disk, comptime T: type, content: *T, sector_offset: u64, commit_memory_to_disk: bool) !void {
        try disk.callbacks.write(disk, asBytes(content), sector_offset, commit_memory_to_disk);
    }

    pub inline fn read_slice(disk: *Disk, comptime T: type, len: usize, sector_offset: u64, provided_buffer: ?[]const u8) ![]T {
        const element_count_per_sector = @divExact(disk.sector_size, @sizeOf(T));
        const sector_count = @divExact(len, element_count_per_sector);
        const read_result = try disk.callbacks.read(disk, sector_count, sector_offset, provided_buffer);
        if (read_result.sector_count != sector_count) @panic("wtf");
        const result = @ptrCast([*]T, @alignCast(@alignOf(T), read_result.buffer))[0..len];
        return result;
    }

    pub inline fn write_slice(disk: *Disk, comptime T: type, slice: []const T, sector_offset: u64, commit_memory_to_disk: bool) !void {
        try disk.callbacks.write(disk, sliceAsBytes(slice), sector_offset, commit_memory_to_disk);
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
            assert(@enumToInt(Operation.read) == 0);
            assert(@enumToInt(Operation.write) == 1);
        }
    };

    pub const PartitionRange = extern struct {
        first_lba: u64,
        last_lba: u64,
    };

    pub const Image = extern struct {
        disk: Disk,
        buffer_ptr: [*]u8,

        const File = struct {
            handle: lib.File,
            size: usize,
        };

        pub fn fromZero(sector_count: usize, sector_size: u16) !Image {
            const disk_bytes = try host.allocateZeroMemory(sector_count * sector_size);
            var disk_image = Image{
                .disk = .{
                    .type = .memory,
                    .callbacks = .{
                        .read = read,
                        .write = write,
                    },
                    .disk_size = disk_bytes.len,
                    .sector_size = sector_size,
                },
                .buffer_ptr = disk_bytes.ptr,
            };

            return disk_image;
        }

        pub fn fromFile(file_path: []const u8, sector_size: u16, allocator: lib.Allocator) !Image {
            const disk_memory = try host.cwd().readFileAlloc(allocator, file_path, lib.maxInt(usize));

            var disk_image = Image{
                .disk = .{
                    .type = .memory,
                    .callbacks = .{
                        .read = read,
                        .write = write,
                    },
                    .disk_size = disk_memory.len,
                    .sector_size = sector_size,
                },
                .buffer_ptr = disk_memory.ptr,
            };

            return disk_image;
        }

        pub inline fn get_buffer(disk_image: Image) []u8 {
            return disk_image.buffer_ptr[0..disk_image.disk.disk_size];
        }

        pub fn get_file(file_path: []const u8) !File {
            const handle = try lib.cwd().openFile(file_path, .{});
            return File{
                .handle = handle,
                .size = try handle.getEndPos(),
            };
        }

        pub fn read(disk: *Disk, sector_count: u64, sector_offset: u64, provided_buffer: ?[]const u8) Disk.ReadError!Disk.ReadResult {
            assert(provided_buffer == null);
            const disk_image = @fieldParentPtr(Image, "disk", disk);
            assert(disk_image.disk.disk_size > 0);
            assert(sector_count > 0);
            //assert(disk.disk.disk_size == disk.buffer.items.len);
            const byte_count = sector_count * disk_image.disk.sector_size;
            const byte_offset = sector_offset * disk_image.disk.sector_size;
            if (byte_offset + byte_count > disk.disk_size) {
                log.debug("Trying to read {} bytes with {} offset: {}. Disk size: {}\n", .{ byte_count, byte_offset, byte_offset + byte_count, disk.disk_size });
                return Disk.ReadError.read_error;
            }
            return .{
                .buffer = disk_image.get_buffer()[byte_offset .. byte_offset + byte_count].ptr,
                .sector_count = sector_count,
            };
        }

        pub fn write(disk: *Disk, bytes: []const u8, sector_offset: u64, commit_memory_to_disk: bool) Disk.WriteError!void {
            const need_write = !(disk.type == .memory and !commit_memory_to_disk);
            log.debug("Trying to write {} bytes to sector offset 0x{x}. Actually write: {}", .{ bytes.len, sector_offset, commit_memory_to_disk });
            if (need_write) {
                log.debug("Actually writing {} bytes to sector offset 0x{x}", .{ bytes.len, sector_offset });
                const disk_image = @fieldParentPtr(Image, "disk", disk);
                assert(disk_image.disk.disk_size > 0);
                //assert(disk.disk.partition_count == 1);
                assert(bytes.len > 0);
                //assert(disk.disk.disk_size == disk.buffer.items.len);
                const byte_offset = sector_offset * disk_image.disk.sector_size;
                if (byte_offset + bytes.len > disk_image.disk.disk_size) return Disk.WriteError.write_error;
                lib.copy(u8, disk_image.get_buffer()[byte_offset .. byte_offset + bytes.len], bytes);
            }
        }
    };
};
