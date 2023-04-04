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

const disk_image_builder = @import("disk_image_builder");
const ImageDescription = disk_image_builder.ImageDescription;
const DiskImage = disk_image_builder.DiskImage;
const format = disk_image_builder.format;

const dap_file_read = 0x600;
const file_copy_offset = 0x10000;

pub fn main() anyerror!void {
    var arena_allocator = host.ArenaAllocator.init(host.page_allocator);
    defer arena_allocator.deinit();
    var wrapped_allocator = lib.Allocator.wrap(arena_allocator.allocator());

    const arguments = (try host.allocateArguments(wrapped_allocator.unwrap_zig()))[1..];
    if (arguments.len != lib.fields(Configuration).len) {
        log.err("Arguments len: {}. Field count: {}", .{ arguments.len, lib.fields(Configuration).len });
        return Error.wrong_arguments;
    }

    const configuration = blk: {
        var cfg: Configuration = undefined;
        inline for (lib.fields(Configuration), 0..) |configuration_field, index| {
            @field(cfg, configuration_field.name) = lib.stringToEnum(configuration_field.type, arguments[index]) orelse {
                log.err("Index: {} Arg: {s}", .{ index, arguments[index] });
                return Error.wrong_arguments;
            };
        }

        break :blk cfg;
    };

    //const suffix = try lib.concat(wrapped_allocator.unwrap_zig(), u8, &.{ "_", @tagName(bootloader_id), "_", @tagName(architecture), "_", @tagName(boot_protocol) });

    // TODO: use a format with hex support
    const image_config = try lib.ImageConfig.get(wrapped_allocator.unwrap_zig(), lib.ImageConfig.default_path);
    var disk_image = try DiskImage.fromZero(image_config.sector_count, image_config.sector_size);
    const disk = &disk_image.disk;
    const gpt_cache = try GPT.create(disk, null);
    var partition_name_buffer: [256]u16 = undefined;
    const partition_name = blk: {
        const partition_index = try lib.unicode.utf8ToUtf16Le(&partition_name_buffer, image_config.partition.name);
        break :blk partition_name_buffer[0..partition_index];
    };

    const config_file_name = "files";
    const configuration_file = try host.cwd().readFileAlloc(wrapped_allocator.unwrap_zig(), "config/" ++ config_file_name, max_file_length);

    switch (image_config.partition.filesystem) {
        .fat32 => {
            const filesystem = .fat32;
            const gpt_partition_cache = try gpt_cache.addPartition(filesystem, partition_name, image_config.partition.first_lba, gpt_cache.header.last_usable_lba, null);
            const fat_partition_cache = try format(gpt_cache.disk, .{
                .first_lba = gpt_partition_cache.partition.first_lba,
                .last_lba = gpt_partition_cache.partition.last_lba,
            }, null);

            var files_parser = bootloader.File.Parser.init(configuration_file);

            const cpu_driver_name = blk: {
                var maybe_cpu_driver_name: ?[]const u8 = null;
                while (try files_parser.next()) |file_descriptor| {
                    if (file_descriptor.type == .cpu_driver) {
                        if (maybe_cpu_driver_name != null) @panic("More than one CPU driver");
                        maybe_cpu_driver_name = file_descriptor.guest;
                    }

                    const host_relative_path = try lib.concat(wrapped_allocator.unwrap_zig(), u8, &.{ file_descriptor.host_path, "/", file_descriptor.host_base, switch (file_descriptor.type) {
                        .cpu_driver, .init => try lib.Suffix.cpu_driver.fromConfiguration(wrapped_allocator.unwrap_zig(), configuration, "_"),
                        else => "",
                    } });
                    // log.debug("Host relative path: {s}", .{host_relative_path});
                    const file_content = try host.cwd().readFileAlloc(wrapped_allocator.unwrap_zig(), host_relative_path, max_file_length);
                    try fat_partition_cache.makeNewFile(file_descriptor.guest, file_content, wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));
                }

                break :blk maybe_cpu_driver_name orelse unreachable;
            };

            const file_content = configuration_file;
            const guest_file_path = try lib.concat(wrapped_allocator.unwrap_zig(), u8, &.{ "/", config_file_name });
            try fat_partition_cache.makeNewFile(guest_file_path, file_content, wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));

            switch (configuration.bootloader) {
                .limine => {
                    // log.debug("Installing Limine HDD", .{});
                    try limine.Installer.install(disk_image.get_buffer(), false, null);
                    // log.debug("Ended installing Limine HDD", .{});
                    const limine_installable_path = "src/bootloader/limine/installables";
                    const limine_installable_dir = try host.cwd().openDir(limine_installable_path, .{});

                    const limine_cfg = blk: {
                        var limine_cfg_generator = LimineCFG{
                            .buffer = host.ArrayList(u8).init(wrapped_allocator.unwrap_zig()),
                        };
                        try limine_cfg_generator.addField("TIMEOUT", "0");
                        try limine_cfg_generator.addEntryName("Rise");
                        try limine_cfg_generator.addField("PROTOCOL", "limine");
                        try limine_cfg_generator.addField("DEFAULT_ENTRY", "0");
                        try limine_cfg_generator.addField("KERNEL_PATH", try lib.concat(wrapped_allocator.unwrap_zig(), u8, &.{ "boot:///", cpu_driver_name }));
                        files_parser = bootloader.File.Parser.init(configuration_file);
                        while (try files_parser.next()) |file_descriptor| {
                            try limine_cfg_generator.addField("MODULE_PATH", try lib.concat(wrapped_allocator.unwrap_zig(), u8, &.{ "boot:///", file_descriptor.guest[1..] }));
                        }
                        break :blk limine_cfg_generator.buffer.items;
                    };

                    try fat_partition_cache.makeNewFile("/limine.cfg", limine_cfg, wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));
                    const limine_sys = try limine_installable_dir.readFileAlloc(wrapped_allocator.unwrap_zig(), "limine.sys", max_file_length);
                    try fat_partition_cache.makeNewFile("/limine.sys", limine_sys, wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));

                    switch (configuration.architecture) {
                        .x86_64 => {
                            try fat_partition_cache.makeNewDirectory("/EFI", wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));
                            try fat_partition_cache.makeNewDirectory("/EFI/BOOT", wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));
                            try fat_partition_cache.makeNewFile("/EFI/BOOT/BOOTX64.EFI", try limine_installable_dir.readFileAlloc(wrapped_allocator.unwrap_zig(), "BOOTX64.EFI", max_file_length), wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));
                        },
                        else => unreachable,
                    }
                },
                .rise => switch (configuration.boot_protocol) {
                    .bios => {
                        const loader_file_path = try lib.concat(wrapped_allocator.unwrap_zig(), u8, &.{ "zig-cache/", try lib.Suffix.bootloader.fromConfiguration(wrapped_allocator.unwrap_zig(), configuration, "bootloader_") });
                        // log.debug("trying to load file: {s}", .{loader_file_path});
                        const loader_file = try host.cwd().readFileAlloc(wrapped_allocator.unwrap_zig(), loader_file_path, max_file_length);
                        const partition_first_usable_lba = gpt_partition_cache.gpt.header.first_usable_lba;
                        assert((fat_partition_cache.partition_range.first_lba - partition_first_usable_lba) * disk.sector_size > lib.alignForward(loader_file.len, disk.sector_size));
                        try disk.write_slice(u8, loader_file, partition_first_usable_lba, true);

                        // Build our own assembler
                        const boot_disk_mbr_lba = 0;
                        const boot_disk_mbr = try disk.read_typed_sectors(BootDisk, boot_disk_mbr_lba, null, .{});
                        // const dap_offset = @offsetOf(BootDisk, "dap");
                        // _ = dap_offset;
                        // lib.log.debug("DAP offset: 0x{x}", .{dap_offset});
                        const aligned_file_size = lib.alignForward(loader_file.len, 0x200);
                        const text_section_guess = lib.alignBackwardGeneric(u32, @ptrCast(*align(1) u32, &loader_file[0x18]).*, 0x1000);
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

                        try boot_disk_mbr.fill(wrapped_allocator.unwrap_zig(), dap);
                        try disk.write_typed_sectors(BootDisk, boot_disk_mbr, boot_disk_mbr_lba, false);
                    },
                    .uefi => {
                        const loader_file_path = try lib.concat(wrapped_allocator.unwrap_zig(), u8, &.{ "zig-cache/", try lib.Suffix.bootloader.fromConfiguration(wrapped_allocator.unwrap_zig(), configuration, "bootloader_"), ".efi" });
                        const loader_file = try host.cwd().readFileAlloc(wrapped_allocator.unwrap_zig(), loader_file_path, max_file_length);
                        try fat_partition_cache.makeNewDirectory("/EFI", wrapped_allocator.unwrap(), null, 0);
                        try fat_partition_cache.makeNewDirectory("/EFI/BOOT", wrapped_allocator.unwrap(), null, 0);
                        try fat_partition_cache.makeNewFile("/EFI/BOOT/BOOTX64.EFI", loader_file, wrapped_allocator.unwrap(), null, 0);
                    },
                },
            }
        },
        else => @panic("Filesystem not supported"),
    }

    const disk_image_path = try lib.concat(wrapped_allocator.unwrap_zig(), u8, &.{ "zig-cache/", image_config.image_name, try lib.Suffix.image.fromConfiguration(wrapped_allocator.unwrap_zig(), configuration, "_"), ".hdd" });
    try host.cwd().writeFile(disk_image_path, disk_image.get_buffer());
}

pub const BootDisk = extern struct {
    bpb: MBR.BIOSParameterBlock.DOS7_1_79,
    code: [code_byte_count]u8,
    gdt: GDT,
    gdt_descriptor: GDT.Descriptor,
    dap: MBR.DAP align(2),
    partitions: [4]MBR.LegacyPartition align(2),
    signature: [2]u8 = [_]u8{ 0x55, 0xaa },

    const code_byte_count = 0x10d;

    const GDT = bootloader.arch.x86_64.GDT;

    const hlt = [_]u8{0xf4};
    const clc = [_]u8{0xf8};
    const cli = [_]u8{0xfa};
    const sti = [_]u8{0xfb};
    const cld = [_]u8{0xfc};

    const xor = 0x31;
    const xor_si_si_16 = [_]u8{ xor, 0xf6 };
    const push_ds = [_]u8{0x1e};
    const mov_ds_si = [_]u8{ 0x8e, 0xde };
    const mov_es_si = [_]u8{ 0x8e, 0xc6 };
    const mov_ss_si = [_]u8{ 0x8e, 0xd6 };
    const mov_sp_stack_top = [_]u8{0xbc} ++ lib.asBytes(&bootloader.BIOS.stack_top).*;
    const mov_bx_0xaa55 = [_]u8{ 0xbb, 0xaa, 0x55 };
    const cmp_bx_0xaa55 = [_]u8{ 0x81, 0xfb, 0x55, 0xaa };

    const jc = 0x72;
    const jne = 0x75;

    const mov_eax_cr0 = [_]u8{ 0x0f, 0x20, 0xc0 };
    const mov_cr0_eax = [_]u8{ 0x0f, 0x22, 0xc0 };

    const code_32 = @offsetOf(GDT, "code_32");
    const data_32 = @offsetOf(GDT, "data_32");

    const reload_data_segments_32 = [_]u8{
        0xb8, data_32, 0x00, 0x00, 0x00, // mov eax, 0x10
        0x8e, 0xd8, // mov ds, ax
        0x8e, 0xc0, // mov es, ax
        0x8e, 0xe0, // mov fs, ax
        0x8e, 0xe8, // mov gs, ax
        0x8e, 0xd0, // mov ss, ax
    };
    const xor_eax_eax = [_]u8{ xor, 0xc8 };
    const xor_ebx_ebx = [_]u8{ xor, 0xdb };
    const nop = [_]u8{0x90};
    const rep_movsb = [_]u8{ 0xf3, 0xa4 };

    fn or_ax(imm8: u8) [4]u8 {
        return .{ 0x66, 0x83, 0xc8, imm8 };
    }

    fn int(interrupt_number: u8) [2]u8 {
        return .{ 0xcd, interrupt_number };
    }

    fn mov_cx(imm16: u16) [3]u8 {
        const imm_bytes = lib.asBytes(&imm16);
        return .{ 0xb9, imm_bytes[0], imm_bytes[1] };
    }

    fn mov_di(imm16: u16) [3]u8 {
        const imm_bytes = lib.asBytes(&imm16);
        return .{ 0xbf, imm_bytes[0], imm_bytes[1] };
    }

    fn mov_si(imm16: u16) [3]u8 {
        const imm_bytes = lib.asBytes(&imm16);
        return .{ 0xbe, imm_bytes[0], imm_bytes[1] };
    }

    fn mov_ah(imm8: u8) [2]u8 {
        return .{ 0xb4, imm8 };
    }

    pub fn fill(mbr: *BootDisk, allocator: lib.ZigAllocator, dap: MBR.DAP) !void {
        // Hardcoded jmp to end of FAT32 BPB
        const jmp_to_end_of_bpb = .{ 0xeb, @sizeOf(MBR.BIOSParameterBlock.DOS7_1_79) - 2 };
        mbr.bpb.dos3_31.dos2_0.jmp_code = jmp_to_end_of_bpb ++ nop;
        mbr.dap = dap;
        mbr.gdt = .{};
        mbr.gdt_descriptor = .{
            .limit = @sizeOf(GDT) - 1,
            .address = bootloader.BIOS.mbr_offset + @offsetOf(BootDisk, "gdt"),
        };
        var assembler = Assembler{
            .boot_disk = mbr,
            .patches = host.ArrayList(Patch).init(allocator),
            .labels = host.ArrayList(Label.Offset).init(allocator),
        };
        defer assembler.patch();

        // 16-bit
        assembler.addInstruction(&cli);
        assembler.addInstruction(&xor_si_si_16);
        assembler.addInstruction(&mov_ds_si);
        assembler.addInstruction(&mov_es_si);
        assembler.addInstruction(&mov_ss_si);
        assembler.addInstruction(&mov_sp_stack_top);
        assembler.addInstruction(&mov_si(0x7c00));
        assembler.addInstruction(&mov_di(bootloader.BIOS.mbr_offset));
        assembler.addInstruction(&mov_cx(0x200));
        assembler.addInstruction(&cld);
        assembler.addInstruction(&rep_movsb);
        try assembler.far_jmp_16(0x0, .reload_cs_16);

        try assembler.add_instruction_with_label(&sti, .reload_cs_16);
        assembler.addInstruction(&mov_ah(0x41));
        assembler.addInstruction(&mov_bx_0xaa55);
        assembler.addInstruction(&int(0x13));
        try assembler.jcc(jc, .error16);
        assembler.addInstruction(&cmp_bx_0xaa55);
        try assembler.jcc(jne, .error16);
        try assembler.add_instruction_with_label(&mov_ah(0x42), .read_sectors);
        try assembler.mov_si(.dap);
        assembler.addInstruction(&clc);
        assembler.addInstruction(&int(0x13));

        try assembler.jcc(jc, .error16);
        // Save real mode
        try assembler.lgdt_16(.gdt_descriptor);
        assembler.addInstruction(&cli);
        assembler.addInstruction(&mov_eax_cr0);
        assembler.addInstruction(&or_ax(1));
        assembler.addInstruction(&mov_cr0_eax);
        try assembler.far_jmp_16(code_32, .protected_mode);

        try assembler.add_instruction_with_label(&cli, .error16);
        assembler.addInstruction(&hlt);

        // 32-bit
        try assembler.add_instruction_with_label(&reload_data_segments_32, .protected_mode);
        assembler.addInstruction(&xor_eax_eax);
        assembler.addInstruction(&xor_ebx_ebx);

        assembler.addInstruction(&[_]u8{0xbe} ++ lib.asBytes(&@as(u32, 0x600)));
        assembler.addInstruction(&[_]u8{0xbf} ++ lib.asBytes(&@as(u32, 0x10000)));
        const aligned_file_size = @as(u32, dap.sector_count * 0x200);
        assembler.addInstruction(&[_]u8{0xb9} ++ lib.asBytes(&aligned_file_size));
        assembler.addInstruction(&cld);
        assembler.addInstruction(&[_]u8{ 0xf3, 0xa4 });

        assembler.addInstruction(&[_]u8{0xbd} ++ lib.asBytes(&@as(u32, 0x10000)));

        //b0:  66 8b 5d 2a             mov    bx,WORD PTR [rbp+0x2a] // BX: Program header size
        assembler.addInstruction(&.{ 0x66, 0x8b, 0x5d, 0x2a });
        //b4:	66 8b 45 2c          	mov    ax,WORD PTR [rbp+0x2c] // AX: Program header count
        assembler.addInstruction(&.{ 0x66, 0x8b, 0x45, 0x2c });
        //b8:	8b 55 1c             	mov    edx,DWORD PTR [rbp+0x1c] // EDX: Program header offset
        assembler.addInstruction(&.{ 0x8b, 0x55, 0x1c });
        //bb:	01 ea                	add    edx,ebp // EDX: program header base address
        assembler.addInstruction(&.{ 0x01, 0xea });
        //bd:	83 3a 01             	cmp    DWORD PTR [rdx],0x1 // [EDX]: Program header type. Compare if it is PT_LOAD
        try assembler.add_instruction_with_label(&.{ 0x83, 0x3a, 0x01 }, .elf_loader_loop);
        //c0:	75 0d                	jne    0xcf // Continue if not PT_LOAD
        try assembler.jcc(jne, .elf_loader_loop_continue);
        //c2:	89 ee                	mov    esi,ebp // ESI: ELF base address
        assembler.addInstruction(&.{ 0x89, 0xee });
        //c4:	03 72 04             	add    esi,DWORD PTR [rdx+0x4] // ESI: program segment address, source of the memcpy

        assembler.addInstruction(&.{ 0x03, 0x72, 0x04 });
        //c7:	8b 7a 0c             	mov    edi,DWORD PTR [rdx+0xc] // EDI: program segment physical address, destination of the memcpy
        assembler.addInstruction(&.{ 0x8b, 0x7a, 0x0c });
        //ca:	8b 4a 10             	mov    ecx,DWORD PTR [rdx+0x10] // ECX: program header file size, bytes to memcpy
        assembler.addInstruction(&.{ 0x8b, 0x4a, 0x10 });
        //cd:	f3 a4                	rep movs BYTE PTR es:[rdi],BYTE PTR ds:[rsi]
        assembler.addInstruction(&.{ 0xf3, 0xa4 });
        //cf:	01 da                	add    edx,ebx
        try assembler.add_instruction_with_label(&.{ 0x01, 0xda }, .elf_loader_loop_continue);
        //d1:	48                      dec    eax
        assembler.addInstruction(&.{0x48});
        // jnz loop
        const jnz = jne;
        try assembler.jcc(jnz, .elf_loader_loop);
        //d5:	8b 5d 18             	mov    ebx,DWORD PTR [rbp+0x18]
        assembler.addInstruction(&.{ 0x8b, 0x5d, 0x18 });
        //d8:	ff e3                	jmp    rbx
        assembler.addInstruction(&.{ 0xff, 0xe3 });
        // log.debug("MBR code length: 0x{x}/0x{x}", .{ assembler.code_index, assembler.boot_disk.code.len });
    }

    const Label = enum {
        reload_cs_16,
        error16,
        read_sectors,
        dap,
        dap_pointer,
        gdt_descriptor,
        protected_mode,
        elf_loader_loop,
        elf_loader_loop_continue,

        const Offset = struct {
            label: Label,
            offset: u8,
        };
    };

    const Patch = struct {
        label: Label,
        label_size: u8,
        label_offset: u8,
        // For relative labels, instruction len to compute RIP-relative address
        // For absolute labels, offset in which to introduce a 8-bit absolute offset
        label_type: enum {
            relative,
            absolute,
        },
        label_section: enum {
            code,
            data,
        },
        instruction_starting_offset: u8,
        instruction_len: u8,
    };

    pub const Assembler = struct {
        boot_disk: *BootDisk,
        code_index: u8 = 0,
        patches: host.ArrayList(Patch),
        labels: host.ArrayList(Label.Offset),

        pub inline fn addInstruction(assembler: *Assembler, instruction_bytes: []const u8) void {
            assert(assembler.code_index + instruction_bytes.len <= assembler.boot_disk.code.len);
            // lib.print("[0x{x:0>4}] ", .{bootloader.BIOS.mbr_offset + @offsetOf(BootDisk, "code") + assembler.code_index});
            // for (instruction_bytes) |byte| {
            //     lib.print("{x:0>2} ", .{byte});
            // }
            // lib.print("\n", .{});
            lib.copy(u8, assembler.boot_disk.code[assembler.code_index .. assembler.code_index + instruction_bytes.len], instruction_bytes);
            assembler.code_index += @intCast(u8, instruction_bytes.len);
        }

        pub fn add_instruction_with_label(assembler: *Assembler, instruction_bytes: []const u8, label: Label) !void {
            try assembler.labels.append(.{ .label = label, .offset = assembler.code_index });
            assembler.addInstruction(instruction_bytes);
        }

        pub fn far_jmp_16(assembler: *Assembler, segment: u16, label: Label) !void {
            const segment_bytes = lib.asBytes(&segment);
            const offset_bytes = lib.asBytes(&bootloader.BIOS.mbr_offset);
            const instruction_bytes = [_]u8{ 0xea, offset_bytes[0], offset_bytes[1], segment_bytes[0], segment_bytes[1] };
            try assembler.patches.append(.{
                .label = label,
                .label_size = @sizeOf(u16),
                .label_offset = 1,
                .label_type = .absolute,
                .label_section = .code,
                .instruction_starting_offset = assembler.code_index,
                .instruction_len = instruction_bytes.len,
            });
            assembler.addInstruction(&instruction_bytes);
        }

        pub fn jcc(assembler: *Assembler, jmp_opcode: u8, label: Label) !void {
            const instruction_bytes = [_]u8{ jmp_opcode, 0x00 };
            try assembler.patches.append(.{
                .label = label,
                .label_size = @sizeOf(u8),
                .label_offset = 1,
                .label_type = .relative,
                .label_section = .code,
                .instruction_starting_offset = assembler.code_index,
                .instruction_len = instruction_bytes.len,
            });
            assembler.addInstruction(&instruction_bytes);
        }

        pub fn mov_si(assembler: *Assembler, label: Label) !void {
            const instruction_bytes = [_]u8{ 0xbe, 0x00, 0x00 };
            try assembler.patches.append(.{
                .label = label,
                .label_size = @sizeOf(u16),
                .label_offset = 1,
                .label_type = .absolute,
                .label_section = .data,
                .instruction_starting_offset = assembler.code_index,
                .instruction_len = instruction_bytes.len,
            });
            assembler.addInstruction(&instruction_bytes);
        }

        pub fn lgdt_16(assembler: *Assembler, label: Label) !void {
            const instruction_bytes = [_]u8{ 0x0f, 0x01, 0x16, 0x00, 0x00 };
            try assembler.patches.append(.{
                .label = label,
                .label_size = @sizeOf(u16),
                .label_offset = 3,
                .label_type = .absolute,
                .label_section = .data,
                .instruction_starting_offset = assembler.code_index,
                .instruction_len = instruction_bytes.len,
            });
            assembler.addInstruction(&instruction_bytes);
        }

        pub fn mov_ebp_dword_ptr(assembler: *Assembler, label: Label) !void {
            const instruction_bytes = [_]u8{ 0x8b, 0x2d, 0x00, 0x00, 0x00, 0x00 };
            try assembler.patches.append(.{
                .label = label,
                .label_size = @sizeOf(u16),
                .label_offset = 2,
                .label_type = .absolute,
                .label_section = .data,
                .instruction_starting_offset = assembler.code_index,
                .instruction_len = instruction_bytes.len,
            });
            assembler.addInstruction(&instruction_bytes);
        }

        pub fn patch(assembler: *Assembler) void {
            var patched: usize = 0;

            next_patch: for (assembler.patches.items) |patch_descriptor| {
                const index = patch_descriptor.instruction_starting_offset + patch_descriptor.label_offset;
                // log.debug("Trying to patch instruction. Section: {s}. Label: {s}. Label size: {}. Label type: {s}", .{ @tagName(patch_descriptor.label_section), @tagName(patch_descriptor.label), patch_descriptor.label_size, @tagName(patch_descriptor.label_type) });
                switch (patch_descriptor.label_section) {
                    .code => for (assembler.labels.items) |label_descriptor| {
                        if (patch_descriptor.label == label_descriptor.label) {
                            switch (patch_descriptor.label_type) {
                                .absolute => {
                                    assert(patch_descriptor.label_size == @sizeOf(u16));
                                    @ptrCast(*align(1) u16, &assembler.boot_disk.code[index]).* = bootloader.BIOS.mbr_offset + @offsetOf(BootDisk, "code") + label_descriptor.offset;
                                },
                                .relative => {
                                    assert(patch_descriptor.label_size == @sizeOf(u8));
                                    assert(patch_descriptor.label_section == .code);
                                    const computed_after_instruction_offset = patch_descriptor.instruction_starting_offset + patch_descriptor.instruction_len;
                                    const operand_a = @intCast(isize, label_descriptor.offset);
                                    const operand_b = @intCast(isize, computed_after_instruction_offset);
                                    const diff = @bitCast(u8, @intCast(i8, operand_a - operand_b));
                                    @ptrCast(*align(1) u8, &assembler.boot_disk.code[index]).* = diff;
                                },
                            }

                            // const instruction_start = bootloader.BIOS.mbr_offset + @offsetOf(BootDisk, "code") + patch_descriptor.instruction_starting_offset;
                            // lib.print("[0x{x:0>4}] ", .{instruction_start});
                            // const instruction_bytes = assembler.boot_disk.code[patch_descriptor.instruction_starting_offset .. patch_descriptor.instruction_starting_offset + patch_descriptor.instruction_len];
                            // for (instruction_bytes) |byte| {
                            //     lib.print("{x:0>2} ", .{byte});
                            // }
                            // lib.print("\n", .{});
                            patched += 1;
                            continue :next_patch;
                        }
                    },
                    .data => {
                        // log.debug("Data: {s}", .{@tagName(patch_descriptor.label)});
                        const dap_offset = @offsetOf(BootDisk, "dap");
                        // log.debug("DAP offset: 0x{x}", .{dap_offset});
                        switch (patch_descriptor.label_type) {
                            .absolute => {
                                assert(patch_descriptor.label_size == @sizeOf(u16));
                                const ptr = bootloader.BIOS.mbr_offset + @as(u16, switch (patch_descriptor.label) {
                                    .dap => dap_offset,
                                    .gdt_descriptor => @offsetOf(BootDisk, "gdt_descriptor"),
                                    .dap_pointer => dap_offset + @offsetOf(MBR.DAP, "offset"),
                                    else => @panic("unreachable tag"),
                                });
                                // log.debug("Ptr patched: 0x{x}", .{ptr});
                                @ptrCast(*align(1) u16, &assembler.boot_disk.code[index]).* = ptr;
                            },
                            .relative => @panic("unreachable relative"),
                        }

                        // log.debug("Patched instruction:", .{});
                        // const instruction_start = bootloader.BIOS.mbr_offset + @offsetOf(BootDisk, "code") + patch_descriptor.instruction_starting_offset;
                        // lib.print("[0x{x:0>4}] ", .{instruction_start});
                        // const instruction_bytes = assembler.boot_disk.code[patch_descriptor.instruction_starting_offset .. patch_descriptor.instruction_starting_offset + patch_descriptor.instruction_len];
                        // for (instruction_bytes) |byte| {
                        //     lib.print("{x:0>2} ", .{byte});
                        // }
                        // lib.print("\n", .{});

                        patched += 1;
                        continue :next_patch;
                    },
                }

                // log.debug("Patch count: {}. Patched count: {}", .{ assembler.patches.items.len, patched });
                assert(patched == assembler.patches.items.len);
            }
        }
    };

    comptime {
        assert(@sizeOf(@This()) == 0x200);
    }
};

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

const Error = error{
    wrong_arguments,
    not_implemented,
};
