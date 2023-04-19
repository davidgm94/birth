const host = @import("host");
const lib = @import("lib");
const bootloader = @import("bootloader");
const limine = bootloader.limine;

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
    user_programs_not_found,
    image_configuration_path_not_found,
    disk_image_path_not_found,
    wrong_arguments,
    not_implemented,
};

fn readFileAbsolute(allocator: *lib.Allocator.Wrapped, absolute_file_path: []const u8) ![]const u8 {
    return try ((try host.fs.openFileAbsolute(absolute_file_path, .{})).readToEndAlloc(allocator.zigUnwrap(), max_file_length));
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
                assert(@enumToInt(argument_type) == 0);
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
            .bootloader = argument_bootloader,
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

            try fat_partition_cache.makeNewFile("/cpu", try readFileAbsolute(&wrapped_allocator, arguments_result.cpu), wrapped_allocator.unwrap(), null, 0);
            assert(arguments_result.user_programs.len == 1);
            const init_program = arguments_result.user_programs[0];
            assert(lib.containsAtLeast(u8, init_program, 1, "init"));
            try fat_partition_cache.makeNewFile("/init", try readFileAbsolute(&wrapped_allocator, init_program), wrapped_allocator.unwrap(), null, 0);
            try fat_partition_cache.makeNewFile("/font", try host.cwd().readFileAlloc(wrapped_allocator.zigUnwrap(), "resources/zap-light16.psf", max_file_length), wrapped_allocator.unwrap(), null, 0);

            switch (configuration.bootloader) {
                .limine => {
                    // log.debug("Installing Limine HDD", .{});
                    try limine.Installer.install(disk_image.getBuffer(), false, null);
                    // log.debug("Ended installing Limine HDD", .{});
                    const limine_installable_path = "src/bootloader/limine/installables";
                    const limine_installable_dir = try host.cwd().openDir(limine_installable_path, .{});

                    const limine_cfg = blk: {
                        var limine_cfg_generator = LimineCFG{
                            .buffer = host.ArrayList(u8).init(wrapped_allocator.zigUnwrap()),
                        };
                        try limine_cfg_generator.addField("TIMEOUT", "0");
                        try limine_cfg_generator.addEntryName("Rise");
                        try limine_cfg_generator.addField("PROTOCOL", "limine");
                        try limine_cfg_generator.addField("DEFAULT_ENTRY", "0");
                        try limine_cfg_generator.addField("KERNEL_PATH", try lib.concat(wrapped_allocator.zigUnwrap(), u8, &.{ "boot:///", lib.default_cpu_name }));
                        inline for (lib.fields(bootloader.File.Type)) |file_type_enum| {
                            const file_type = @field(bootloader.File.Type, file_type_enum.name);
                            const file_name = @tagName(file_type);
                            try limine_cfg_generator.addField("MODULE_PATH", "boot:///" ++ file_name);
                        }
                        break :blk limine_cfg_generator.buffer.items;
                    };

                    try fat_partition_cache.makeNewFile("/limine.cfg", limine_cfg, wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));
                    const limine_sys = try limine_installable_dir.readFileAlloc(wrapped_allocator.zigUnwrap(), "limine.sys", max_file_length);
                    try fat_partition_cache.makeNewFile("/limine.sys", limine_sys, wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));

                    switch (configuration.architecture) {
                        .x86_64 => {
                            try fat_partition_cache.makeNewDirectory("/EFI", wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));
                            try fat_partition_cache.makeNewDirectory("/EFI/BOOT", wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));
                            try fat_partition_cache.makeNewFile("/EFI/BOOT/BOOTX64.EFI", try limine_installable_dir.readFileAlloc(wrapped_allocator.zigUnwrap(), "BOOTX64.EFI", max_file_length), wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));
                        },
                        else => unreachable,
                    }
                },
                .rise => switch (configuration.boot_protocol) {
                    .bios => {
                        const loader_file_path = arguments_result.bootloader.?;
                        const loader_file = try readFileAbsolute(&wrapped_allocator, loader_file_path);
                        const partition_first_usable_lba = gpt_partition_cache.gpt.header.first_usable_lba;
                        assert((fat_partition_cache.partition_range.first_lba - partition_first_usable_lba) * disk.sector_size > lib.alignForward(loader_file.len, disk.sector_size));
                        try disk.write_slice(u8, loader_file, partition_first_usable_lba, true);

                        // Build our own assembler
                        const boot_disk_mbr_lba = 0;
                        const boot_disk_mbr = try disk.read_typed_sectors(BootDisk, boot_disk_mbr_lba, null, .{});
                        // const dap_offset = @offsetOf(BootDisk, "dap");
                        // _ = dap_offset;
                        // lib.log.debug("DAP offset: 0x{x}", .{dap_offset});
                        const aligned_file_size = lib.alignForward(loader_file.len, disk.sector_size);
                        const text_section_guess = lib.alignBackwardGeneric(u32, @ptrCast(*align(1) const u32, &loader_file[0x18]).*, 0x1000);
                        if (lib.maxInt(u32) - text_section_guess < aligned_file_size) @panic("unexpected size");
                        const dap_top = bootloader.BIOS.stack_top - bootloader.BIOS.stack_size;
                        if (aligned_file_size > dap_top) host.panic("File size: 0x{x} bytes", .{aligned_file_size});
                        // log.debug("DAP top: 0x{x}. Aligned file size: 0x{x}", .{ dap_top, aligned_file_size });
                        const dap = MBR.DAP{
                            .sector_count = @intCast(u16, @divExact(aligned_file_size, disk.sector_size)),
                            .offset = dap_file_read,
                            .segment = 0x0,
                            .lba = partition_first_usable_lba,
                        };

                        if (dap_top - dap.offset < aligned_file_size) {
                            @panic("unable to fit file read from disk");
                        }

                        // if (dap.offset - bootloader.BIOS.loader_start < aligned_file_size) {
                        //     @panic("unable to fit loaded executable in memory");
                        // }

                        try boot_disk_mbr.fill(wrapped_allocator.zigUnwrap(), dap);
                        try disk.write_typed_sectors(BootDisk, boot_disk_mbr, boot_disk_mbr_lba, false);
                    },
                    .uefi => {
                        const loader_file_path = arguments_result.bootloader.?;
                        const loader_file = try host.cwd().readFileAlloc(wrapped_allocator.zigUnwrap(), loader_file_path, max_file_length);
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
