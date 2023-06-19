const host = @import("host");
const lib = @import("lib");
const bios = @import("bios");
const limine_installer = @import("limine_installer");

const assert = lib.assert;
const log = lib.log.scoped(.DiskImageBuilder);

const Disk = lib.Disk;
const GPT = lib.PartitionTable.GPT;
const MBR = lib.PartitionTable.MBR;
const FAT32 = lib.Filesystem.FAT32;

const max_file_length = lib.maxInt(usize);

const Configuration = lib.Configuration;

const disk_image_builder = @import("../disk_image_builder.zig");
const ImageDescription = disk_image_builder.ImageDescription;
const DiskImage = disk_image_builder.DiskImage;
const format = disk_image_builder.format;

const BootDisk = @import("boot_disk.zig").BootDisk;

const dap_file_read = 0x600;
const file_copy_offset = 0x10000;

const Error = error{
    configuration_wrong_argument,
    configuration_not_found,
    cpu_not_found,
    bootloader_path_not_found,
    user_programs_not_found,
    image_configuration_path_not_found,
    disk_image_path_not_found,
    wrong_arguments,
    not_implemented,
};

fn readFileAbsolute(allocator: *lib.Allocator.Wrapped, absolute_file_path: []const u8) ![]const u8 {
    return try ((try host.fs.openFileAbsolute(absolute_file_path, .{})).readToEndAlloc(allocator.zigUnwrap(), max_file_length));
}

fn readFileAbsoluteToArrayList(array_list: *host.ArrayList(u8), absolute_file_path: []const u8) !void {
    const file = try host.fs.openFileAbsolute(absolute_file_path, .{});
    try file.reader().readAllArrayList(array_list, lib.maxInt(usize));
}

fn addFileToBundle(file: host.fs.File, file_list: *host.ArrayList(u8), name: []const u8, file_contents: *host.ArrayList(u8)) !void {
    try file_contents.appendNTimes(0, lib.alignForward(usize, file_contents.items.len, 0x10) - file_contents.items.len);
    const offset = file_contents.items.len;
    try file.reader().readAllArrayList(file_contents, lib.maxInt(usize));
    const stat = try file.stat();
    try file_list.writer().writeIntLittle(u32, @as(u32, @intCast(offset)));
    try file_list.writer().writeIntLittle(u32, @as(u32, @intCast(stat.size)));
    try file_list.writer().writeIntLittle(u8, @as(u8, @intCast(name.len)));
    try file_list.appendSlice(name);
}

pub fn main() anyerror!void {
    var arena_allocator = host.ArenaAllocator.init(host.page_allocator);
    defer arena_allocator.deinit();
    var wrapped_allocator = lib.Allocator.wrap(arena_allocator.allocator());

    const arguments = (try host.allocateArguments(wrapped_allocator.zigUnwrap()))[1..];

    const arguments_result: lib.ArgumentParser.DiskImageBuilder.Result = blk: {
        var argument_parser = lib.ArgumentParser.DiskImageBuilder{};
        var argument_configuration: ?Configuration = null;
        var argument_bootloader: ?[]const u8 = null;
        var argument_cpu: ?[]const u8 = null;
        var argument_user_programs: ?[]const []const u8 = null;
        var argument_image_configuration_path: ?[]const u8 = null;
        var argument_disk_image_path: ?[]const u8 = null;
        var argument_index: usize = 0;

        while (argument_parser.next()) |argument_type| switch (argument_type) {
            .disk_image_path => {
                assert(@intFromEnum(argument_type) == 0);
                argument_disk_image_path = arguments[argument_index];
                argument_index += 1;
            },
            .configuration => {
                argument_configuration = undefined;
                const configuration = &argument_configuration.?;
                inline for (lib.fields(Configuration)) |field| {
                    @field(configuration, field.name) = lib.stringToEnum(field.type, arguments[argument_index]) orelse return Error.configuration_wrong_argument;
                    argument_index += 1;
                }
            },
            .image_configuration_path => {
                argument_image_configuration_path = arguments[argument_index];
                argument_index += 1;
            },
            .bootloader => {
                const argument = arguments[argument_index];
                argument_index += 1;
                if (!lib.equal(u8, argument, "-")) {
                    argument_bootloader = argument;
                }
            },
            .cpu => {
                argument_cpu = arguments[argument_index];
                argument_index += 1;
            },
            .user_programs => {
                argument_user_programs = arguments[argument_index..];
                argument_index += argument_user_programs.?.len;
            },
        };

        assert(argument_index == arguments.len);
        break :blk .{
            .configuration = argument_configuration orelse return Error.configuration_not_found,
            .disk_image_path = argument_disk_image_path orelse return Error.disk_image_path_not_found,
            .image_configuration_path = argument_image_configuration_path orelse return Error.image_configuration_path_not_found,
            .bootloader = argument_bootloader orelse return Error.bootloader_path_not_found,
            .cpu = argument_cpu orelse return Error.cpu_not_found,
            .user_programs = argument_user_programs orelse return Error.user_programs_not_found,
        };
    };

    const configuration = arguments_result.configuration;

    // TODO: use a format with hex support
    const image_config = try lib.ImageConfig.get(wrapped_allocator.zigUnwrap(), arguments_result.image_configuration_path);
    var disk_image = try DiskImage.fromZero(image_config.sector_count, image_config.sector_size);
    const disk = &disk_image.disk;
    const gpt_cache = try GPT.create(disk, null);
    var partition_name_buffer: [256]u16 = undefined;
    const partition_name = blk: {
        const partition_index = try lib.unicode.utf8ToUtf16Le(&partition_name_buffer, image_config.partition.name);
        break :blk partition_name_buffer[0..partition_index];
    };

    switch (image_config.partition.filesystem) {
        .fat32 => {
            const filesystem = .fat32;
            const gpt_partition_cache = try gpt_cache.addPartition(filesystem, partition_name, image_config.partition.first_lba, gpt_cache.header.last_usable_lba, null);
            const fat_partition_cache = try format(gpt_cache.disk, .{
                .first_lba = gpt_partition_cache.partition.first_lba,
                .last_lba = gpt_partition_cache.partition.last_lba,
            }, null);

            var bundle_file_list = host.ArrayList(u8).init(wrapped_allocator.zigUnwrap());
            var uncompressed = host.ArrayList(u8).init(wrapped_allocator.zigUnwrap());
            // Uncompressed bundle size
            try bundle_file_list.writer().writeIntLittle(u32, 0);
            // Compressed bundle size
            try bundle_file_list.writer().writeIntLittle(u32, 0);
            // (cpu + programs + font) Bundle file count
            try bundle_file_list.writer().writeIntLittle(u32, @as(u32, @intCast(1 + arguments_result.user_programs.len + 1)));

            const cpu_path = arguments_result.cpu;
            const cpu_file = try host.fs.openFileAbsolute(cpu_path, .{});
            const cpu_name = host.basename(cpu_path);
            try addFileToBundle(cpu_file, &bundle_file_list, cpu_name, &uncompressed);

            for (arguments_result.user_programs) |user_program| {
                const file = try host.fs.openFileAbsolute(user_program, .{});
                const name = host.basename(user_program);
                try addFileToBundle(file, &bundle_file_list, name, &uncompressed);
            }

            const font_file = try host.cwd().openFile("resources/zap-light16.psf", .{});
            try addFileToBundle(font_file, &bundle_file_list, "font", &uncompressed);

            var compressed = host.ArrayList(u8).init(wrapped_allocator.zigUnwrap());
            var compressor = try lib.deflate.compressor(wrapped_allocator.zigUnwrap(), compressed.writer(), .{ .level = .best_compression });
            try compressor.writer().writeAll(uncompressed.items);
            try compressor.close();

            // Wait until here because reallocations can happen in the ArrayList
            const bundle_sizes = @as(*align(1) [2]u32, @ptrCast(&bundle_file_list.items[0]));
            bundle_sizes[0] = @as(u32, @intCast(uncompressed.items.len));
            bundle_sizes[1] = @as(u32, @intCast(compressed.items.len));

            // {
            //     var stream = lib.fixedBufferStream(compressed.items);
            //     var decompressor = try lib.deflate.decompressor(wrapped_allocator.zigUnwrap(), stream.reader(), null);
            //     var decompressed = host.ArrayList(u8).init(wrapped_allocator.zigUnwrap());
            //     try decompressor.reader().readAllArrayList(&decompressed, lib.maxInt(usize));
            //     log.debug("DECOMPRESSED AFTER:", .{});
            //     if (decompressor.close()) |err| return err;
            //
            //     for (decompressed.items[0..20], uncompressed.items[0..20]) |byte, before| {
            //         assert(byte == before);
            //         log.debug("Byte: 0x{x}", .{byte});
            //     }
            // }

            try fat_partition_cache.makeNewFile("/files", bundle_file_list.items, wrapped_allocator.unwrap(), null, 0);
            try fat_partition_cache.makeNewFile("/bundle", compressed.items, wrapped_allocator.unwrap(), null, 0);

            const loader_file_path = arguments_result.bootloader;
            const loader_file = try readFileAbsolute(&wrapped_allocator, loader_file_path);

            switch (configuration.bootloader) {
                .limine => {
                    // log.debug("Installing Limine HDD", .{});
                    try limine_installer.install(disk_image.getBuffer(), false, null);
                    // log.debug("Ended installing Limine HDD", .{});
                    const limine_installable_path = "src/bootloader/limine/installables";
                    const limine_installable_dir = try host.cwd().openDir(limine_installable_path, .{});
                    const loader_fat_path = try lib.concat(wrapped_allocator.zigUnwrap(), u8, &.{ "/", host.basename(loader_file_path) });
                    try fat_partition_cache.makeNewFile(loader_fat_path, loader_file, wrapped_allocator.unwrap(), null, 0);

                    const limine_cfg = blk: {
                        var limine_cfg_generator = LimineCFG{
                            .buffer = host.ArrayList(u8).init(wrapped_allocator.zigUnwrap()),
                        };
                        try limine_cfg_generator.addField("TIMEOUT", "0");
                        try limine_cfg_generator.addEntryName("Rise");
                        try limine_cfg_generator.addField("PROTOCOL", "limine");
                        try limine_cfg_generator.addField("DEFAULT_ENTRY", "0");
                        try limine_cfg_generator.addField("KERNEL_PATH", try lib.concat(wrapped_allocator.zigUnwrap(), u8, &.{ "boot:///", loader_fat_path }));

                        try limine_cfg_generator.addField("MODULE_PATH", "boot:////bundle");
                        try limine_cfg_generator.addField("MODULE_PATH", "boot:////files");
                        break :blk limine_cfg_generator.buffer.items;
                    };

                    try fat_partition_cache.makeNewFile("/limine.cfg", limine_cfg, wrapped_allocator.unwrap(), null, @as(u64, @intCast(host.time.milliTimestamp())));
                    const limine_sys = try limine_installable_dir.readFileAlloc(wrapped_allocator.zigUnwrap(), "limine.sys", max_file_length);
                    try fat_partition_cache.makeNewFile("/limine.sys", limine_sys, wrapped_allocator.unwrap(), null, @as(u64, @intCast(host.time.milliTimestamp())));

                    switch (configuration.architecture) {
                        .x86_64 => {
                            try fat_partition_cache.makeNewDirectory("/EFI", wrapped_allocator.unwrap(), null, @as(u64, @intCast(host.time.milliTimestamp())));
                            try fat_partition_cache.makeNewDirectory("/EFI/BOOT", wrapped_allocator.unwrap(), null, @as(u64, @intCast(host.time.milliTimestamp())));
                            try fat_partition_cache.makeNewFile("/EFI/BOOT/BOOTX64.EFI", try limine_installable_dir.readFileAlloc(wrapped_allocator.zigUnwrap(), "BOOTX64.EFI", max_file_length), wrapped_allocator.unwrap(), null, @as(u64, @intCast(host.time.milliTimestamp())));
                        },
                        else => unreachable,
                    }
                },
                .rise => switch (configuration.boot_protocol) {
                    .bios => {
                        const partition_first_usable_lba = gpt_partition_cache.gpt.header.first_usable_lba;
                        assert((fat_partition_cache.partition_range.first_lba - partition_first_usable_lba) * disk.sector_size > lib.alignForward(usize, loader_file.len, disk.sector_size));
                        try disk.writeSlice(u8, loader_file, partition_first_usable_lba, true);

                        // Build our own assembler
                        const boot_disk_mbr_lba = 0;
                        const boot_disk_mbr = try disk.readTypedSectors(BootDisk, boot_disk_mbr_lba, null, .{});
                        // const dap_offset = @offsetOf(BootDisk, "dap");
                        // _ = dap_offset;
                        // lib.log.debug("DAP offset: 0x{x}", .{dap_offset});
                        const aligned_file_size = lib.alignForward(usize, loader_file.len, disk.sector_size);
                        const text_section_guess = lib.alignBackward(u32, @as(*align(1) const u32, @ptrCast(&loader_file[0x18])).*, 0x1000);
                        if (lib.maxInt(u32) - text_section_guess < aligned_file_size) @panic("unexpected size");
                        const dap_top = bios.stack_top - bios.stack_size;
                        if (aligned_file_size > dap_top) host.panic("File size: 0x{x} bytes", .{aligned_file_size});
                        // log.debug("DAP top: 0x{x}. Aligned file size: 0x{x}", .{ dap_top, aligned_file_size });
                        const dap = MBR.DAP{
                            .sector_count = @as(u16, @intCast(@divExact(aligned_file_size, disk.sector_size))),
                            .offset = dap_file_read,
                            .segment = 0x0,
                            .lba = partition_first_usable_lba,
                        };

                        if (dap_top - dap.offset < aligned_file_size) {
                            @panic("unable to fit file read from disk");
                        }

                        // if (dap.offset - bios.loader_start < aligned_file_size) {
                        //     @panic("unable to fit loaded executable in memory");
                        // }

                        try boot_disk_mbr.fill(wrapped_allocator.zigUnwrap(), dap);
                        try disk.writeTypedSectors(BootDisk, boot_disk_mbr, boot_disk_mbr_lba, false);
                    },
                    .uefi => {
                        try fat_partition_cache.makeNewDirectory("/EFI", wrapped_allocator.unwrap(), null, 0);
                        try fat_partition_cache.makeNewDirectory("/EFI/BOOT", wrapped_allocator.unwrap(), null, 0);
                        try fat_partition_cache.makeNewFile("/EFI/BOOT/BOOTX64.EFI", loader_file, wrapped_allocator.unwrap(), null, 0);
                    },
                },
            }
        },
        else => @panic("Filesystem not supported"),
    }

    const image_file = try host.fs.createFileAbsolute(arguments_result.disk_image_path, .{});
    try image_file.writeAll(disk_image.getBuffer());
}

const LimineCFG = struct {
    buffer: host.ArrayList(u8),

    pub fn addField(limine_cfg: *LimineCFG, field_name: []const u8, field_value: []const u8) !void {
        try limine_cfg.buffer.appendSlice(field_name);
        try limine_cfg.buffer.append('=');
        try limine_cfg.buffer.appendSlice(field_value);
        try limine_cfg.buffer.append('\n');
    }

    pub fn addEntryName(limine_cfg: *LimineCFG, entry_name: []const u8) !void {
        try limine_cfg.buffer.append(':');
        try limine_cfg.buffer.appendSlice(entry_name);
        try limine_cfg.buffer.append('\n');
    }
};
