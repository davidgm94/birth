const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.DISK_IMAGE_BUILDER);
const FAT32 = lib.Filesystem.FAT32;
const GPT = lib.PartitionTable.GPT;
const host = @import("host");
const limine_installer = @import("limine_installer");

const disk_image_builder = @import("../disk_image_builder.zig");
const ImageDescription = disk_image_builder.ImageDescription;
const DiskImage = disk_image_builder.DiskImage;

const LoopbackDevice = struct {
    name: []const u8,
    mount_dir: ?[]const u8 = null,

    fn start(loopback_device: *LoopbackDevice, allocator: lib.ZigAllocator, image_path: []const u8) !void {
        try host.spawnProcess(&.{ "./tools/loopback_start.sh", image_path, loopback_device.name }, allocator);
    }

    fn end(loopback_device: *LoopbackDevice, allocator: lib.ZigAllocator) !void {
        loopback_device.mount_dir = null;
        try host.spawnProcess(&.{ "./tools/loopback_end.sh", loopback_device.name }, allocator);
        try host.cwd().deleteFile(loopback_device.name);
    }

    fn mount(loopback_device: *LoopbackDevice, allocator: lib.ZigAllocator, mount_dir: []const u8) !MountedPartition {
        try host.cwd().makePath(mount_dir);
        try host.spawnProcess(&.{ "./tools/loopback_mount.sh", loopback_device.name, mount_dir }, allocator);
        loopback_device.mount_dir = mount_dir;

        return MountedPartition{
            .loopback_device = loopback_device.*,
        };
    }
};

const MountedPartition = struct {
    loopback_device: LoopbackDevice,

    fn mkdir(partition: MountedPartition, allocator: lib.ZigAllocator, dir: []const u8) !void {
        try host.spawnProcess(&.{ "sudo", "mkdir", "-p", try partition.join_with_root(allocator, dir) }, allocator);
    }

    fn join_with_root(partition: MountedPartition, allocator: lib.ZigAllocator, path: []const u8) ![]const u8 {
        const mount_dir = partition.get_mount_dir();
        const slices_to_join: []const []const u8 = if (path[0] == '/') &.{ mount_dir, path } else &.{ mount_dir, "/", path };
        const joint_path = try lib.concat(allocator, u8, slices_to_join);
        return joint_path;
    }

    pub fn get_mount_dir(partition: MountedPartition) []const u8 {
        const mount_dir = partition.loopback_device.mount_dir orelse @panic("get_mount_dir");
        return mount_dir;
    }

    fn copy_file(partition: MountedPartition, allocator: lib.ZigAllocator, file_path: []const u8, file_content: []const u8) !void {
        // TODO: make this work for Windows?
        const last_slash_index = lib.lastIndexOf(u8, file_path, "/") orelse @panic("fat32: copy file last slash");
        const file_name = host.basename(file_path);
        assert(file_name.len > 0);
        try host.cwd().writeFile(file_name, file_content);
        const dir = file_path[0..if (last_slash_index == 0) 1 else last_slash_index];
        const destination_dir = try partition.join_with_root(allocator, dir);
        const mkdir_process_args = &.{ "sudo", "mkdir", "-p", destination_dir };
        try host.spawnProcess(mkdir_process_args, allocator);
        const copy_process_args = &.{ "sudo", "cp", "-v", file_name, destination_dir };
        try host.spawnProcess(copy_process_args, allocator);
        try host.cwd().deleteFile(file_name);
    }

    fn end(partition: *MountedPartition, allocator: lib.ZigAllocator) !void {
        const mount_dir = partition.loopback_device.mount_dir orelse @panic("mount partition end");
        host.sync();
        try host.spawnProcess(&.{ "sudo", "umount", mount_dir }, allocator);
        host.spawnProcess(&.{ "sudo", "rm", "-rf", mount_dir }, allocator) catch |err| {
            switch (err) {
                host.ExecutionError.failed => {},
                else => return err,
            }
        };
    }
};

const ShellImage = struct {
    path: []const u8,
    description: ImageDescription,

    fn createFAT(image: ShellImage, allocator: lib.ZigAllocator) !void {
        const megabytes = @divExact(image.description.disk_sector_count * image.description.disk_sector_size, lib.mb);
        try host.spawnProcess(&.{ "dd", "if=/dev/zero", "bs=1M", "count=0", try lib.allocPrint(allocator, "seek={d}", .{megabytes}), try lib.allocPrint(allocator, "of={s}", .{image.path}) }, allocator);

        try host.spawnProcess(&.{ "parted", "-s", image.path, "mklabel", "gpt" }, allocator);
        try host.spawnProcess(&.{ "parted", "-s", image.path, "mkpart", image.description.partition_name, @tagName(image.description.partition_filesystem), try lib.allocPrint(allocator, "{d}s", .{image.description.partition_start_lba}), "100%" }, allocator);
        try host.spawnProcess(&.{ "parted", "-s", image.path, "set", "1", "esp", "on" }, allocator);
    }

    fn toDiskImage(image: ShellImage, allocator: lib.ZigAllocator) !DiskImage {
        return try DiskImage.fromFile(image.path, @as(u16, @intCast(image.description.disk_sector_size)), allocator);
    }

    fn delete(image: ShellImage) !void {
        try host.cwd().deleteFile(image.path);
    }
};

const File = struct {
    path: []const u8,
    content: []const u8,
};

const limine_directories = [_][]const u8{
    "/EFI", "/EFI/BOOT",
};

const limine_files = [_]File{
    .{ .path = "/limine.cfg", .content = @embedFile("../../bootloader/limine/installables/limine.cfg") },
    .{ .path = "/limine.sys", .content = @embedFile("../../bootloader/limine/installables/limine.sys") },
};

test "Limine barebones" {
    lib.testing.log_level = .debug;

    //
    // Using an arena allocator because it doesn't care about memory leaks
    var arena_allocator = host.ArenaAllocator.init(host.page_allocator);
    defer arena_allocator.deinit();

    var wrapped_allocator = lib.Allocator.wrap(arena_allocator.allocator());

    const deploy_limine = true;

    switch (lib.os) {
        .linux => {
            const image = ImageDescription{
                .partition_start_lba = 0x800,
                .disk_sector_count = 131072,
                .disk_sector_size = lib.default_sector_size,
                .partition_name = "ESP",
                .partition_filesystem = .fat32,
            };

            const test_path = "zig-cache/test_original.hdd";
            const test_image = ShellImage{
                .path = test_path,
                .description = image,
            };
            test_image.delete() catch {};

            try test_image.createFAT(wrapped_allocator.zigUnwrap());
            if (deploy_limine and disk_image_builder.deploy(test_path, &limine_installer.hdd, limine_installer.hdd.len) != 0) {
                @panic("asjdkajsd");
            }

            var loopback_device = LoopbackDevice{ .name = "loopback_device" };
            try loopback_device.start(wrapped_allocator.zigUnwrap(), test_path);

            log.debug("Formatting", .{});
            try host.spawnProcess(&.{ "./tools/format_loopback_fat32.sh", loopback_device.name }, wrapped_allocator.zigUnwrap());

            const mount_dir = "image_mount";

            var partition = try loopback_device.mount(wrapped_allocator.zigUnwrap(), mount_dir);

            for (limine_directories) |directory| {
                try partition.mkdir(wrapped_allocator.zigUnwrap(), directory);
            }

            for (limine_files) |file| {
                try partition.copy_file(wrapped_allocator.zigUnwrap(), file.path, file.content);
            }

            try partition.end(wrapped_allocator.zigUnwrap());
            try loopback_device.end(wrapped_allocator.zigUnwrap());

            var original_disk_image = try test_image.toDiskImage(wrapped_allocator.zigUnwrap());
            const original_gpt_cache = try GPT.Partition.Cache.fromPartitionIndex(&original_disk_image.disk, 0, wrapped_allocator.unwrap());
            const original_fat_cache = try FAT32.Cache.fromGPTPartitionCache(wrapped_allocator.unwrap(), original_gpt_cache);

            var disk_image = try DiskImage.fromZero(image.disk_sector_count, image.disk_sector_size);
            const gpt_partition_cache = try disk_image.createFAT(image, original_gpt_cache);

            const original_buffer = original_disk_image.getBuffer();
            const my_buffer = disk_image.getBuffer();

            if (deploy_limine) {
                try limine_installer.install(my_buffer, false, null);
            }

            const fat_partition_cache = try disk_image_builder.format(gpt_partition_cache.gpt.disk, .{
                .first_lba = gpt_partition_cache.partition.first_lba,
                .last_lba = gpt_partition_cache.partition.last_lba,
            }, original_fat_cache.mbr);

            for (limine_directories) |directory| {
                log.debug("Creating directory: {s}", .{directory});
                try fat_partition_cache.makeNewDirectory(directory, null, original_fat_cache, @as(u64, @intCast(host.time.milliTimestamp())));
            }

            for (limine_files) |file| {
                log.debug("Creating file: {s}", .{file.path});
                try fat_partition_cache.makeNewFile(file.path, file.content, wrapped_allocator.unwrap(), original_fat_cache, @as(u64, @intCast(host.time.milliTimestamp())));
            }

            var diff_count: u32 = 0;
            for (my_buffer, 0..) |mb, i| {
                const ob = original_buffer[i];
                const diff = ob != mb;
                if (diff) {
                    log.debug("[0x{x}] Diff. Expected: 0x{x}. Actual: 0x{x}", .{ i, ob, mb });
                }
                diff_count += @intFromBool(diff);
            }

            if (diff_count > 0) {
                log.err("Diff count: {}", .{diff_count});
            }
            try lib.testing.expectEqualSlices(u8, original_buffer, my_buffer);

            try test_image.delete();
        },
        else => {},
    }
}
