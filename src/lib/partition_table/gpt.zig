const GPT = @This();

const lib = @import("../../lib.zig");
const assert = lib.assert;
const kb = lib.kb;
const mb = lib.mb;
const gb = lib.gb;
const CRC32 = lib.CRC32;
const Disk = lib.Disk;
const Filesystem = lib.Filesystem;
const FAT32 = Filesystem.FAT32;
const log = lib.log.scoped(.GPT);
const MBR = lib.PartitionTable.MBR;
const GUID = lib.uefi.Guid;

pub const default_max_partition_count = 128;
pub const min_block_size = 0x200;
pub const max_block_size = 0x1000;

pub const Header = extern struct {
    signature: [8]u8 = "EFI PART".*,
    revision: [4]u8 = .{ 0, 0, 1, 0 },
    header_size: u32 = @sizeOf(Header),
    header_crc32: u32 = 0,
    reserved: u32 = 0,
    header_lba: u64,
    backup_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    disk_guid: GUID,
    partition_array_lba: u64,
    partition_entry_count: u32,
    partition_entry_size: u32 = @sizeOf(Partition),
    partition_array_crc32: u32,
    reserved1: [420]u8 = [1]u8{0} ** 420,

    pub fn update_crc32(header: *Header) void {
        header.header_crc32 = 0;
        header.header_crc32 = CRC32.compute(lib.asBytes(header)[0..header.header_size]);
    }

    pub fn get_partition_count_in_sector(header: *const Header, disk: *const Disk) u32 {
        return @divExact(disk.sector_size, header.partition_entry_size);
    }

    pub fn format(header: *const Header, comptime _: []const u8, _: lib.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try lib.internal_format(writer, "GPT header:\n", .{});
        try lib.internal_format(writer, "\tSignature: {s}\n", .{header.signature});
        try lib.internal_format(writer, "\tRevision: {any}\n", .{header.revision});
        try lib.internal_format(writer, "\tHeader size: {}\n", .{header.header_size});
        try lib.internal_format(writer, "\tHeader CRC32: 0x{x}\n", .{header.header_crc32});
        try lib.internal_format(writer, "\tHeader LBA: 0x{x}\n", .{header.header_lba});
        try lib.internal_format(writer, "\tAlternate header LBA: 0x{x}\n", .{header.backup_lba});
        try lib.internal_format(writer, "\tFirst usable LBA: 0x{x}\n", .{header.first_usable_lba});
        try lib.internal_format(writer, "\tLast usable LBA: 0x{x}\n", .{header.last_usable_lba});
        try lib.internal_format(writer, "\tDisk GUID: {}\n", .{header.disk_guid});
        try lib.internal_format(writer, "\tPartition array LBA: 0x{x}\n", .{header.partition_array_lba});
        try lib.internal_format(writer, "\tPartition entry count: {}\n", .{header.partition_entry_count});
        try lib.internal_format(writer, "\tPartition entry size: {}\n", .{header.partition_entry_size});
        try lib.internal_format(writer, "\tPartition array CRC32: 0x{x}\n", .{header.partition_array_crc32});
    }

    pub fn compare(header: *const Header, other: *align(1) const Header) void {
        log.debug("{}", .{header});
        log.debug("{}", .{other});

        if (!lib.equal(u8, &header.signature, &other.signature)) {
            log.debug("Signature mismatch: {s}, {s}", .{ header.signature, other.signature });
        }
        if (!lib.equal(u8, &header.revision, &other.revision)) {
            log.debug("Revision mismatch: {any}, {any}", .{ header.revision, other.revision });
        }
        if (header.header_size != other.header_size) {
            log.debug("Header size mismatch: {}, {}", .{ header.header_size, other.header_size });
        }
        if (header.header_crc32 != other.header_crc32) {
            log.debug("Header CRC32 mismatch: {}, {}", .{ header.header_crc32, other.header_crc32 });
        }
        if (header.header_lba != other.header_lba) {
            log.debug("Header LBA mismatch: {}, {}", .{ header.header_lba, other.header_lba });
        }
        if (header.backup_lba != other.backup_lba) {
            log.debug("Backup LBA mismatch: {}, {}", .{ header.backup_lba, other.backup_lba });
        }
        if (header.first_usable_lba != other.first_usable_lba) {
            log.debug("First usable LBA mismatch: {}, {}", .{ header.first_usable_lba, other.first_usable_lba });
        }
        if (header.last_usable_lba != other.last_usable_lba) {
            log.debug("Last usable LBA mismatch: {}, {}", .{ header.last_usable_lba, other.last_usable_lba });
        }
        if (!header.disk_guid.eql(other.disk_guid)) {
            log.debug("Disk GUID mismatch: {}, {}", .{ header.disk_guid, other.disk_guid });
        }
        if (header.partition_array_lba != other.partition_array_lba) {
            log.debug("Partition array LBA mismatch: {}, {}", .{ header.partition_array_lba, other.partition_array_lba });
        }
        if (header.partition_entry_count != other.partition_entry_count) {
            log.debug("Partition entry count mismatch: {}, {}", .{ header.partition_entry_count, other.partition_entry_count });
        }
        if (header.partition_entry_size != other.partition_entry_size) {
            log.debug("Partition entry size mismatch: {}, {}", .{ header.partition_entry_size, other.partition_entry_size });
        }
        if (header.partition_array_crc32 != other.partition_array_crc32) {
            log.debug("Partition array CRC32 mismatch: {}, {}", .{ header.partition_array_crc32, other.partition_array_crc32 });
        }
    }

    pub const Cache = extern struct {
        mbr: *MBR.Partition,
        header: *GPT.Header,
        partition_entries: [*]GPT.Partition,
        disk: *Disk,

        pub fn get_free_partition_slot(cache: Cache) !*GPT.Partition {
            assert(cache.header.partition_entry_size == @sizeOf(GPT.Partition));
            for (cache.partition_entries[0..cache.header.partition_entry_count]) |*partition_entry| {
                if (partition_entry.first_lba == 0 and partition_entry.last_lba == 0) {
                    return partition_entry;
                }
            }

            unreachable;
        }

        pub fn get_partition_index(cache: Cache, partition: *GPT.Partition) u32 {
            assert(cache.header.partition_entry_size == @sizeOf(GPT.Partition));
            return @divExact(@intCast(u32, @ptrToInt(partition) - @ptrToInt(cache.partition_entries)), cache.header.partition_entry_size);
        }

        pub fn get_partition_sector(cache: Cache, partition: *GPT.Partition) u32 {
            return get_partition_index(cache, partition) / cache.header.get_partition_count_in_sector(cache.disk);
        }

        pub inline fn update_partition_entry(cache: Cache, partition: *GPT.Partition, new_value: GPT.Partition) !void {
            assert(cache.header.partition_entry_size == @sizeOf(GPT.Partition));
            const partition_entries = cache.partition_entries[0..cache.header.partition_entry_count];
            const partition_entry_bytes = lib.sliceAsBytes(partition_entries);
            partition.* = new_value;
            cache.header.partition_array_crc32 = CRC32.compute(partition_entry_bytes);
            cache.header.update_crc32();

            const backup_gpt_header = try cache.disk.read_typed_sectors(GPT.Header, cache.header.backup_lba);
            backup_gpt_header.partition_array_crc32 = cache.header.partition_array_crc32;
            backup_gpt_header.update_crc32();

            const partition_entry_sector_offset = cache.get_partition_sector(partition);
            const partition_entry_byte_offset = partition_entry_sector_offset * cache.disk.sector_size;
            // Only commit to disk the modified sector
            const partition_entry_modified_sector_bytes = partition_entry_bytes[partition_entry_byte_offset .. partition_entry_byte_offset + cache.disk.sector_size];
            try cache.disk.write_slice(u8, partition_entry_modified_sector_bytes, cache.header.partition_array_lba + partition_entry_sector_offset, false);
            // Force write because for memory disk we only hold a pointer to the main partition entry array
            try cache.disk.write_slice(u8, partition_entry_modified_sector_bytes, backup_gpt_header.partition_array_lba + partition_entry_sector_offset, true);
            try cache.disk.write_typed_sectors(GPT.Header, cache.header, cache.header.header_lba, false);
            try cache.disk.write_typed_sectors(GPT.Header, backup_gpt_header, backup_gpt_header.header_lba, false);
        }

        pub fn add_partition(cache: Cache, comptime filesystem: lib.Filesystem.Type, partition_name: []const u16, lba_start: u64, lba_end: u64, gpt_partition: ?*const GPT.Partition) !GPT.Partition.Cache {
            // TODO: check if we are not overwriting a partition
            // TODO: check filesystem specific stuff
            const new_partition_entry = try cache.get_free_partition_slot();
            try update_partition_entry(cache, new_partition_entry, GPT.Partition{
                .partition_type_guid = switch (filesystem) {
                    .fat32 => efi_guid,
                    else => unreachable,
                },
                .unique_partition_guid = if (gpt_partition) |gpt_part| gpt_part.unique_partition_guid else get_random_guid(),
                .first_lba = lba_start,
                .last_lba = lba_end,
                .attributes = .{},
                .partition_name = blk: {
                    var name = [1]u16{0} ** 36;
                    lib.copy(u16, &name, partition_name);
                    break :blk name;
                },
            });

            return .{
                .gpt = cache,
                .partition = new_partition_entry,
            };
        }

        pub fn load(disk: *Disk) !GPT.Header.Cache {
            //mbr: *MBR.Partition,
            //header: *GPT.Header,
            //partition_entries: [*]GPT.Partition,
            //disk: *Disk,
            const mbr_lba = MBR.default_lba;
            const mbr = try disk.read_typed_sectors(MBR.Partition, mbr_lba);
            const primary_gpt_header_lba = mbr_lba + 1;
            const gpt_header = try disk.read_typed_sectors(GPT.Header, primary_gpt_header_lba);
            assert(gpt_header.partition_entry_size == @sizeOf(GPT.Partition));
            const partition_entries = try disk.read_slice(GPT.Partition, gpt_header.partition_entry_count, gpt_header.partition_array_lba);

            return .{
                .mbr = mbr,
                .header = gpt_header,
                .partition_entries = partition_entries.ptr,
                .disk = disk,
            };
        }
    };

    comptime {
        assert(@sizeOf(Header) == 0x200);
    }

    pub fn get(disk: *Disk) !*GPT.Header {
        return try disk.read_typed_sectors(GPT.Header, 1);
    }

    pub fn get_backup(gpt_header: *GPT.Header, disk: *Disk) !*GPT.Header {
        return try disk.read_typed_sectors(GPT.Header, gpt_header.backup_lba);
    }
};

var prng = lib.random.DefaultPrng.init(0);
pub fn get_random_guid() GUID {
    const random_array = blk: {
        var arr: [16]u8 = undefined;
        const random = prng.random();
        random.bytes(&arr);
        break :blk arr;
    };
    var guid = GUID{
        .time_low = (@as(u32, random_array[0]) << 24) | (@as(u32, random_array[1]) << 16) | (@as(u32, random_array[2]) << 8) | random_array[3],
        .time_mid = (@as(u16, random_array[4]) << 8) | random_array[5],
        .time_high_and_version = (@as(u16, random_array[6]) << 8) | random_array[7],
        .clock_seq_high_and_reserved = random_array[8],
        .clock_seq_low = random_array[9],
        .node = .{ random_array[10], random_array[11], random_array[12], random_array[13], random_array[14], random_array[15] },
    };

    guid.clock_seq_high_and_reserved = (2 << 6) | (guid.clock_seq_high_and_reserved >> 2);
    guid.time_high_and_version = (4 << 12) | (guid.time_high_and_version >> 4);

    return guid;
}

pub const efi_system_partition_guid = GUID{ .time_low = 0xC12A7328, .time_mid = 0xF81F, .time_hi_and_version = 0x11D2, .clock_seq_hi_and_reserved = 0xBA, .clock_seq_low = 0x4B, .node = [_]u8{ 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B } };
pub const microsoft_basic_data_partition_guid = GUID{ .time_low = 0xEBD0A0A2, .time_mid = 0xB9E5, .time_hi_and_version = 0x4433, .clock_seq_hi_and_reserved = 0x87, .clock_seq_low = 0xC0, .node = [_]u8{ 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7 } };

pub const Partition = extern struct {
    partition_type_guid: GUID,
    unique_partition_guid: GUID,
    first_lba: u64,
    last_lba: u64,
    attributes: Attributes,
    partition_name: [36]u16,

    pub const Cache = extern struct {
        gpt: GPT.Header.Cache,
        partition: *GPT.Partition,

        pub fn from_partition_index(disk: *Disk, partition_index: usize) !GPT.Partition.Cache {
            const gpt_cache = try GPT.Header.Cache.load(disk);
            if (partition_index < gpt_cache.header.partition_entry_count) {
                return .{
                    .gpt = gpt_cache,
                    .partition = &gpt_cache.partition_entries[partition_index],
                };
            }

            unreachable;
        }

        pub fn format(gpt_partition_cache: GPT.Partition.Cache, comptime filesystem: Filesystem.Type, copy_cache: FilesystemCacheTypes[@enumToInt(filesystem)]) !FilesystemCacheTypes[@enumToInt(filesystem)] {
            return try switch (filesystem) {
                .fat32 => fat32: {
                    const partition_range = Disk.PartitionRange{
                        .first_lba = gpt_partition_cache.partition.first_lba,
                        .last_lba = gpt_partition_cache.partition.last_lba,
                    };
                    break :fat32 FAT32.format(gpt_partition_cache.gpt.disk, partition_range, copy_cache.mbr);
                },
                else => unreachable,
            };
        }
    };

    pub const Attributes = packed struct(u64) {
        required_partition: bool = false,
        no_block_io_protocol: bool = false,
        legacy_bios_bootable: bool = false,
        reserved: u45 = 0,
        guid_reserved: u16 = 0,
    };

    pub fn compare(partition: *const Partition, other: *align(1) const Partition) void {
        log.debug("{}", .{partition});
        if (partition.first_lba != other.first_lba) {
            log.debug("First LBA mismatch: 0x{x}, 0x{x}", .{ partition.first_lba, other.first_lba });
        }
        if (partition.last_lba != other.last_lba) {
            log.debug("Last LBA mismatch: 0x{x}, 0x{x}", .{ partition.last_lba, other.last_lba });
        }
        for (partition.partition_name) |partition_char, char_index| {
            const other_char = other.partition_name[char_index];
            if (partition_char != other_char) {
                log.debug("Char is different: {u}(0x{x}), {u}(0x{x})", .{ partition_char, partition_char, other_char, other_char });
            }
        }
    }

    pub fn format(partition: *const Partition, comptime _: []const u8, _: lib.InternalFormatOptions, writer: anytype) @TypeOf(writer).Error!void {
        try lib.internal_format(writer, "GPT partition:\n", .{});
        try lib.internal_format(writer, "\tPartition type GUID: {}\n", .{partition.partition_type_guid});
        try lib.internal_format(writer, "\tUnique partition GUID: {}\n", .{partition.unique_partition_guid});
        try lib.internal_format(writer, "\tFirst LBA: 0x{x}\n", .{partition.first_lba});
        try lib.internal_format(writer, "\tLast LBA: 0x{x}\n", .{partition.last_lba});
        try lib.internal_format(writer, "\tAttributes: {}\n", .{partition.attributes});
        try lib.internal_format(writer, "\tPartition name: {}\n", .{lib.std.unicode.fmtUtf16le(&partition.partition_name)});
    }
};

pub fn create(disk: *Disk, copy_gpt_header: ?*const Header) !GPT.Header.Cache {
    // 1. Create MBR fake partition
    const mbr_lba = MBR.default_lba;
    const mbr = try disk.read_typed_sectors(MBR.Partition, mbr_lba);
    const first_lba = mbr_lba + 1;
    const primary_header_lba = first_lba;
    mbr.partitions[0] = MBR.LegacyPartition{
        .boot_indicator = 0,
        .starting_chs = 0x200,
        .os_type = 0xee,
        .ending_chs = 0xff_ff_ff,
        .first_lba = first_lba,
        .size_in_lba = @intCast(u32, @divExact(disk.disk_size, disk.sector_size) - 1),
    };
    mbr.signature = .{ 0x55, 0xaa };
    try disk.write_typed_sectors(MBR.Partition, mbr, mbr_lba, false);

    // 2. Write GPT header
    const partition_count = default_max_partition_count;
    const partition_array_sector_count = @divExact(@sizeOf(Partition) * partition_count, disk.sector_size);
    // TODO: properly compute header LBA
    const gpt_header = try disk.read_typed_sectors(GPT.Header, first_lba);
    const secondary_header_lba = mbr.partitions[0].size_in_lba;
    const partition_array_lba_start = first_lba + 1;
    const partition_entries = try disk.read_slice(GPT.Partition, partition_count, partition_array_lba_start);
    gpt_header.* = GPT.Header{
        .signature = "EFI PART".*,
        .revision = .{ 0, 0, 1, 0 },
        .header_size = @offsetOf(GPT.Header, "reserved1"),
        .header_crc32 = 0, // TODO
        .header_lba = primary_header_lba,
        .backup_lba = secondary_header_lba,
        .first_usable_lba = partition_array_lba_start + partition_array_sector_count,
        .last_usable_lba = secondary_header_lba - primary_header_lba - partition_array_sector_count,
        .disk_guid = if (copy_gpt_header) |gpth| gpth.disk_guid else get_random_guid(),
        .partition_array_lba = partition_array_lba_start,
        .partition_entry_count = partition_count,
        .partition_array_crc32 = CRC32.compute(lib.sliceAsBytes(partition_entries)),
    };

    gpt_header.update_crc32();
    try disk.write_typed_sectors(GPT.Header, gpt_header, primary_header_lba, false);

    var backup_gpt_header = gpt_header.*;
    backup_gpt_header.partition_array_lba = secondary_header_lba - primary_header_lba - partition_array_sector_count + 1;
    backup_gpt_header.header_lba = gpt_header.backup_lba;
    backup_gpt_header.backup_lba = gpt_header.header_lba;
    backup_gpt_header.update_crc32();
    try disk.write_typed_sectors(GPT.Header, &backup_gpt_header, secondary_header_lba, true);

    return .{
        .mbr = mbr,
        .header = gpt_header,
        .disk = disk,
        .partition_entries = partition_entries.ptr,
    };
}

const efi_guid = GUID{
    .time_low = 0xC12A7328,
    .time_mid = 0xF81F,
    .time_high_and_version = 0x11D2,
    .clock_seq_high_and_reserved = 0xBA,
    .clock_seq_low = 0x4B,
    //00A0C93EC93B
    .node = .{ 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b },
};

const limine_disk_guid = GUID{
    .time_low = 0xD2CB8A76,
    .time_mid = 0xACB3,
    .time_high_and_version = 0x4D4D,
    .clock_seq_high_and_reserved = 0x93,
    .clock_seq_low = 0x55,
    .node = .{ 0xAC, 0xAE, 0xA4, 0x6B, 0x46, 0x92 },
};

const limine_unique_partition_guid = GUID{
    .time_low = 0x26D6E02E,
    .time_mid = 0xEED8,
    .time_high_and_version = 0x4802,
    .clock_seq_high_and_reserved = 0xba,
    .clock_seq_low = 0xa2,
    .node = .{ 0xE5, 0xAA, 0x43, 0x7F, 0xC2, 0xC5 },
};

const FilesystemCacheTypes = blk: {
    var types: [Filesystem.Type.count]type = undefined;
    types[@enumToInt(Filesystem.Type.rise)] = void;
    types[@enumToInt(Filesystem.Type.ext2)] = void;
    types[@enumToInt(Filesystem.Type.fat32)] = FAT32.Cache;

    break :blk types;
};

test "gpt size" {
    comptime {
        assert(@sizeOf(Header) == 0x200);
    }
}

//fn make(step: *lib.build.Step) !void {

//switch (kernel.options.arch) {
//.x86_64 => {
//const x86_64 = kernel.options.arch.x86_64;
//switch (x86_64.boot_protocol) {
//.bios => {
//const barebones = blk: {
//const gpt_partition_cache = try GPT.Partition.Cache.from_partition_index(&barebones_disk_image.descriptor, 0);
//const fat_partition = try FAT32.Cache.from_gpt_partition_cache(gpt_partition_cache);
//break :blk Barebones{
//.gpt_partition_cache = gpt_partition_cache,
//.fat_partition = fat_partition,
//};
//};

//// TODO: mark this with FAT32 GUID (Microsoft basic data partition) and not EFI GUID.Then add a function to modify GUID
//const gpt_partition_cache = try gpt_cache.add_partition(.fat32, lib.std.unicode.utf8ToUtf16LeStringLiteral("ESP"), 0x800, gpt_cache.header.last_usable_lba, barebones.gpt_partition_cache.partition);
//const fat_cache = try gpt_partition_cache.format(.fat32);
//try fat_cache.mkdir("/EFI/BOOT");
//const foo_entry = try barebones.fat_partition.get_directory_entry("/foo", .fail, null);
//try fat_cache.add_file("/foo", "a\n", foo_entry.directory_entry);

//lib.diff(barebones_disk_image.get_buffer(), disk.get_buffer());

//try cwd().writeFile("zig-cache/mydisk.bin", disk.get_buffer());
//unreachable;
////try lib.Disk.image(&disk.descriptor, &.{lib.Disk.min_partition_size}, try cwd().readFileAlloc(kernel.builder.allocator, "zig-cache/mbr.bin", 0x200), 0, 0, .{
////.read = read,
////.write = write,
////});

////try disk.descriptor.verify();
////try cwd().writeFile("zig-cache/disk_image.bin", disk.get_buffer());

////const fat32_partition = try kernel.builder.allocator.create(lib.Filesystem.FAT32.Partition);

////fat32_partition.* = try disk.descriptor.get_partition(0);

////const r = try fat32_partition.create_file("loader.elf");
////_ = r;
////

////const mbr_file = try cwd().readFileAlloc(kernel.builder.allocator, "zig-cache/mbr.bin", max_file_length);
////assert(mbr_file.len == 0x200);
////disk.buffer.appendSliceAssumeCapacity(mbr_file);
////const mbr = @ptrCast(*MBRBIOS, disk.buffer.items.ptr);
////const loader_file = try cwd().readFileAlloc(kernel.builder.allocator, "zig-cache/rise.elf", max_file_length);
////disk.buffer.appendNTimesAssumeCapacity(0, 0x200);
////mbr.dap = .{
////.sector_count = @intCast(u16, lib.align_forward(loader_file.len, 0x200) >> 9),
////.pointer = 0x7e00,
////.lba = disk.buffer.items.len >> 9,
////};
//////std.debug.print("DAP sector count: {}, pointer: 0x{x}, lba: 0x{x}", .{ mbr.dap.sector_count, mbr.dap.pointer, mbr.dap.lba });
//////if (true) unreachable;
//////const a = @ptrToInt(&mbr.dap.pointer);
//////const b = @ptrToInt(mbr);
//////std.debug.print("A: 0x{x}\n", .{a - b});
//////if (true) unreachable;
////disk.buffer.appendSliceAssumeCapacity(loader_file);
//////assert(loader_file.len < 0x200);
////disk.buffer.appendNTimesAssumeCapacity(0, lib.align_forward(loader_file.len, 0x200) - loader_file.len);
//},
//.uefi => unreachable,
//}
//},
//else => unreachable,
//}

////assert(resource_files.len > 0);

////for (resource_files) |filename| {
////const file_content = try cwd().readFileAlloc(kernel.builder.allocator, kernel.builder.fmt("resources/{s}", .{filename}), max_file_length);
////try filesystem.write_file(kernel.allocator, filename, file_content);
////}

////assert(kernel.userspace_programs.len > 0);

////for (kernel.userspace_programs) |program| {
////const filename = program.out_filename;
////const file_path = program.output_path_source.getPath();
////const file_content = try cwd().readFileAlloc(kernel.builder.allocator, file_path, max_file_length);
////try filesystem.write_file(get_allocator(), filename, file_content);
////}

//// TODO: use filesystem
//try cwd().writeFile(kernel.builder.fmt("{s}disk.bin", .{cache_dir}), disk.buffer.items);
//}
