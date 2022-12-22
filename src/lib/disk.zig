const lib = @import("../lib.zig");
const FAT32 = lib.Filesystem.FAT32;
const GPT = lib.PartitionTable.GPT;
const MBR = lib.PartitionTable.MBR;

const ArrayListAligned = lib.ArrayListAligned;
const assert = lib.assert;
const asBytes = lib.asBytes;
const cwd = lib.cwd;
const log = lib.log.scoped(.Disk);
const sliceAsBytes = lib.sliceAsBytes;

pub const Disk = extern struct {
    type: Type,
    disk_size: u64,
    partition_sizes: [GPT.default_max_partition_count]u64 = [1]u64{0} ** GPT.default_max_partition_count,
    sector_size: u16 = 0x200,
    partition_count: u8 = 0,
    callbacks: Callbacks,

    pub const ReadFn = fn (disk: *Disk.Descriptor, sector_count: u64, sector_offset: u64) ReadError![]u8;
    pub const ReadError = error{
        read_error,
    };
    pub const WriteFn = fn (disk: *Disk.Descriptor, bytes: []const u8, offset: u64, commit_memory_to_disk: bool) WriteError!void;
    pub const WriteError = error{
        write_error,
    };

    pub const Callbacks = extern struct {
        read: *const ReadFn,
        write: *const WriteFn,
    };

    pub inline fn read_typed_sectors(disk: *Disk.Descriptor, comptime T: type, sector_offset: u64) !*T {
        const bytes = try disk.callbacks.read(disk, @divExact(@sizeOf(T), disk.sector_size), sector_offset);
        // Don't need to write back since it's a memory disk
        const result = @ptrCast(*T, @alignCast(@alignOf(T), bytes.ptr));
        return result;
    }

    pub inline fn write_typed_sectors(disk: *Disk.Descriptor, comptime T: type, content: *T, sector_offset: u64, commit_memory_to_disk: bool) !void {
        try disk.callbacks.write(disk, asBytes(content), sector_offset, commit_memory_to_disk);
    }

    pub inline fn read_slice(disk: *Disk.Descriptor, comptime T: type, len: usize, sector_offset: u64) ![]T {
        const element_count_per_sector = @divExact(disk.sector_size, @sizeOf(T));
        const sector_count = @divExact(len, element_count_per_sector);
        const bytes = try disk.callbacks.read(disk, sector_count, sector_offset);
        const result = @ptrCast([*]T, @alignCast(@alignOf(T), bytes.ptr))[0..len];
        return result;
    }

    pub inline fn write_slice(disk: *Disk.Descriptor, comptime T: type, slice: []const T, sector_offset: u64, commit_memory_to_disk: bool) !void {
        try disk.callbacks.write(disk, sliceAsBytes(slice), sector_offset, commit_memory_to_disk);
    }

    pub fn verify(disk: *Disk.Descriptor) !void {
        const mbr = try disk.read_typed_sectors(MBR.Struct, 0);
        try mbr.verify(disk);
        unreachable;
    }

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

    pub const PartitionRange = extern struct {
        first_lba: u64,
        last_lba: u64,
    };

    pub const Image = extern struct {
        disk: Disk,
        buffer_ptr: [*]u8,

        const BufferType = ArrayListAligned(u8, 0x200);

        const File = struct {
            handle: lib.File,
            size: usize,
        };

        inline fn get_buffer(disk_image: *Disk.Image) []u8 {
            return disk_image.buffer_ptr[0..disk_image.descriptor.disk_size];
        }

        fn get_file(file_path: []const u8) !File {
            const handle = try cwd().openFile(file_path, .{});
            return File{
                .handle = handle,
                .size = try handle.getEndPos(),
            };
        }

        fn read(disk: *Disk, sector_count: u64, sector_offset: u64) Disk.ReadError![]u8 {
            const disk_image = @fieldParentPtr(Disk.Image, "descriptor", disk);
            assert(disk_image.descriptor.disk_size > 0);
            assert(sector_count > 0);
            //assert(disk.descriptor.disk_size == disk.buffer.items.len);
            const byte_count = sector_count * disk_image.descriptor.sector_size;
            const byte_offset = sector_offset * disk_image.descriptor.sector_size;
            if (byte_offset + byte_count > disk.descriptor.disk_size) {
                log.debug("Trying to read {} bytes with {} offset: {}. Disk size: {}\n", .{ byte_count, byte_offset, byte_offset + byte_count, disk.descriptor.disk_size });
                return Disk.ReadError.read_error;
            }
            const result = disk.get_buffer()[byte_offset .. byte_offset + byte_count];
            return result;
        }

        fn write(disk: *Disk, bytes: []const u8, sector_offset: u64, commit_memory_to_disk: bool) Disk.WriteError!void {
            const need_write = !(disk.type == .memory and !commit_memory_to_disk);
            if (need_write) {
                log.debug("Actually writing {} bytes to sector offset 0x{x}", .{ bytes.len, sector_offset });
                const disk_image = @fieldParentPtr(Disk.Image, "descriptor", disk);
                assert(disk_image.disk.disk_size > 0);
                //assert(disk.descriptor.partition_count == 1);
                assert(bytes.len > 0);
                //assert(disk.descriptor.disk_size == disk.buffer.items.len);
                const byte_offset = sector_offset * disk_image.descriptor.sector_size;
                if (byte_offset + bytes.len > disk_image.descriptor.disk_size) return Disk.WriteError.write_error;
                lib.copy(u8, disk_image.get_buffer()[byte_offset .. byte_offset + bytes.len], bytes);
            }
        }

        //fn make(step: *lib.build.Step) !void {
        //const kernel = @fieldParentPtr(Kernel, "disk_step", step);

        //const disk_bytes = try common.allocate_zero_memory(64 * 1024 * 1024);
        //const disk_sector_count = @divExact(disk_bytes.len, 0x200);
        //common.log.debug("Disk size: 0x{x}", .{disk_sector_count});
        //var disk = DiskImage{
        //.descriptor = .{
        //.type = .memory,
        //.callbacks = .{
        //.read = read,
        //.write = write,
        //},
        //.disk_size = disk_bytes.len,
        //},
        //.buffer_ptr = disk_bytes.ptr,
        //};

        //const barebones_disk_memory = try cwd().readFileAlloc(kernel.builder.allocator, "barebones.hdd", common.max_int(usize));
        //var barebones_disk_image = DiskImage{
        //.descriptor = .{
        //.type = .memory,
        //.callbacks = .{
        //.read = read,
        //.write = write,
        //},
        //.disk_size = barebones_disk_memory.len,
        //},
        //.buffer_ptr = barebones_disk_memory.ptr,
        //};

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

        //const gpt_cache = try GPT.create(&disk.descriptor, barebones.gpt_partition_cache.gpt.header);
        //// TODO: mark this with FAT32 GUID (Microsoft basic data partition) and not EFI GUID.Then add a function to modify GUID
        //const gpt_partition_cache = try gpt_cache.add_partition(.fat32, common.std.unicode.utf8ToUtf16LeStringLiteral("ESP"), 0x800, gpt_cache.header.last_usable_lba, barebones.gpt_partition_cache.partition);
        //const fat_cache = try gpt_partition_cache.format(.fat32);
        //try fat_cache.mkdir("/EFI/BOOT");
        //const foo_entry = try barebones.fat_partition.get_directory_entry("/foo", .fail, null);
        //try fat_cache.add_file("/foo", "a\n", foo_entry.directory_entry);

        //common.diff(barebones_disk_image.get_buffer(), disk.get_buffer());

        //try cwd().writeFile("zig-cache/mydisk.bin", disk.get_buffer());
        //unreachable;
        ////try common.Disk.Descriptor.image(&disk.descriptor, &.{common.Disk.Descriptor.min_partition_size}, try cwd().readFileAlloc(kernel.builder.allocator, "zig-cache/mbr.bin", 0x200), 0, 0, .{
        ////.read = read,
        ////.write = write,
        ////});

        ////try disk.descriptor.verify();
        ////try cwd().writeFile("zig-cache/disk_image.bin", disk.get_buffer());

        ////const fat32_partition = try kernel.builder.allocator.create(common.Filesystem.FAT32.Partition);

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
        ////.sector_count = @intCast(u16, common.align_forward(loader_file.len, 0x200) >> 9),
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
        ////disk.buffer.appendNTimesAssumeCapacity(0, common.align_forward(loader_file.len, 0x200) - loader_file.len);
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
    };
};
