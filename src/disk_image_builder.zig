const host = @import("host.zig");
const lib = @import("lib.zig");
const bootloader = @import("bootloader");
const LimineInstaller = @import("bootloader/limine/installer.zig");

const assert = lib.assert;
const log = lib.log.scoped(.DiskImageBuilder);

const Disk = lib.Disk;
const GPT = lib.PartitionTable.GPT;
const MBR = lib.PartitionTable.MBR;
const FAT32 = lib.Filesystem.FAT32;

const max_file_length = lib.maxInt(usize);

const mbr_offset: u16 = 0xfe00;
const stack_top: u16 = mbr_offset;
const stack_size = 0x1000;

pub const BootDisk = extern struct {
    bpb: MBR.BIOSParameterBlock.DOS7_1_79,
    code: [code_byte_count]u8,
    gdt_32: GDT32,
    dap: MBR.DAP align(2),
    partitions: [4]MBR.LegacyPartition align(2),
    signature: [2]u8 = [_]u8{ 0x55, 0xaa },

    const GDT32 = extern struct {
        register: Register,
        null: Descriptor = .{
            .limit = 0,
            .access = lib.zeroes(Descriptor.AccessByte),
            .limit_and_flags = lib.zeroes(Descriptor.LimitAndFlags),
        },
        code_32: Descriptor = .{
            .access = .{
                .accessed = false,
                .read_write = true,
                .direction_conforming = false,
                .executable = true,
                .code_data_segment = true,
                .dpl = 0,
                .present = true,
            },
            .limit_and_flags = .{
                .limit = 0xf,
                .long_mode = false,
                .protected_mode = true,
                .granularity = true,
            },
        },
        data_32: Descriptor = .{
            .access = .{
                .accessed = false,
                .read_write = true,
                .direction_conforming = false,
                .executable = false,
                .code_data_segment = true,
                .dpl = 0,
                .present = true,
            },
            .limit_and_flags = .{
                .limit = 0xf,
                .long_mode = false,
                .protected_mode = true,
                .granularity = true,
            },
        },
        code_16: Descriptor = .{
            .access = .{
                .accessed = false,
                .read_write = true,
                .direction_conforming = false,
                .executable = true,
                .code_data_segment = true,
                .dpl = 0,
                .present = true,
            },
            .limit_and_flags = .{
                .limit = 0x0,
                .long_mode = false,
                .protected_mode = false,
                .granularity = false,
            },
        },
        data_16: Descriptor = .{
            .access = .{
                .accessed = false,
                .read_write = true,
                .direction_conforming = false,
                .executable = false,
                .code_data_segment = true,
                .dpl = 0,
                .present = true,
            },
            .limit_and_flags = .{
                .limit = 0x0,
                .long_mode = false,
                .protected_mode = false,
                .granularity = false,
            },
        },

        comptime {
            assert(@sizeOf(GDT32) == @sizeOf(Register) + 5 * @sizeOf(Descriptor));
        }

        const Descriptor = extern struct {
            limit: u16 = 0xffff,
            base_low: u16 = 0,
            base_mid: u8 = 0,
            access: AccessByte,
            limit_and_flags: LimitAndFlags,
            base_high: u8 = 0,

            comptime {
                assert(@sizeOf(Descriptor) == @sizeOf(u64));
            }

            const AccessByte = packed struct(u8) {
                accessed: bool = true,
                read_write: bool = false,
                direction_conforming: bool = false,
                executable: bool = false,
                code_data_segment: bool = true,
                dpl: u2 = 0,
                present: bool = true,
            };

            const LimitAndFlags = packed struct(u8) {
                limit: u4,
                reserved: bool = false,
                long_mode: bool,
                protected_mode: bool,
                granularity: bool,
            };
        };

        const Register = extern struct {
            size: u16,
            pointer: u32 align(2),

            comptime {
                assert(@sizeOf(Register) == @sizeOf(u16) + @sizeOf(u32));
            }
        };
    };

    const code_byte_count = 0x126;

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
    const mov_sp_stack_top = [_]u8{0xbc} ++ lib.asBytes(&stack_top).*;
    const mov_bx_0xaa55 = [_]u8{ 0xbb, 0xaa, 0x55 };
    const cmp_bx_0xaa55 = [_]u8{ 0x81, 0xfb, 0x55, 0xaa };

    const jc = 0x72;
    const jne = 0x75;

    const mov_eax_cr0 = [_]u8{ 0x0f, 0x20, 0xc0 };
    const mov_cr0_eax = [_]u8{ 0x0f, 0x22, 0xc0 };
    const reload_data_segments_32 = [_]u8{
        0xb8, 0x10, 0x00, 0x00, 0x00, // mov eax, 0x10
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
        mbr.gdt_32 = GDT32{
            .register = .{
                .size = @sizeOf(GDT32) - @sizeOf(GDT32.Register) - 1,
                .pointer = mbr_offset + @offsetOf(BootDisk, "gdt_32") + @sizeOf(GDT32.Register),
            },
        };
        log.debug("GDT: {}", .{mbr.gdt_32});
        var assembler = Assembler{
            .boot_disk = mbr,
            .patches = host.ArrayList(Patch).init(allocator),
            .labels = host.ArrayList(Label.Offset).init(allocator),
        };
        defer assembler.patch();

        assembler.add_instruction(&cli);
        assembler.add_instruction(&xor_si_si_16);
        assembler.add_instruction(&mov_ds_si);
        assembler.add_instruction(&mov_es_si);
        assembler.add_instruction(&mov_ss_si);
        assembler.add_instruction(&mov_sp_stack_top);
        assembler.add_instruction(&cld);
        assembler.add_instruction(&mov_si(0x7c00));
        assembler.add_instruction(&mov_di(mbr_offset));
        assembler.add_instruction(&mov_cx(0x200));
        assembler.add_instruction(&rep_movsb);
        try assembler.far_jmp_16(0x0, .reload_cs_16);

        try assembler.add_instruction_with_label(&sti, .reload_cs_16);
        assembler.add_instruction(&mov_ah(0x41));
        assembler.add_instruction(&mov_bx_0xaa55);
        assembler.add_instruction(&int(0x13));
        try assembler.jcc(jc, .error16);
        assembler.add_instruction(&cmp_bx_0xaa55);
        try assembler.jcc(jne, .error16);
        try assembler.add_instruction_with_label(&mov_ah(0x42), .read_sectors);
        try assembler.mov_si(.dap);
        assembler.add_instruction(&clc);
        assembler.add_instruction(&int(0x13));

        try assembler.jcc(jc, .error16);
        // Save real mode
        try assembler.lgdt_16(.gdt);
        assembler.add_instruction(&cli);
        assembler.add_instruction(&mov_eax_cr0);
        assembler.add_instruction(&or_ax(1));
        assembler.add_instruction(&mov_cr0_eax);
        try assembler.far_jmp_16(0x8, .protected_mode);

        try assembler.add_instruction_with_label(&cli, .error16);
        assembler.add_instruction(&hlt);

        // TODO: unwrap byte chunk
        try assembler.add_instruction_with_label(&reload_data_segments_32, .protected_mode);
        assembler.add_instruction(&xor_eax_eax);
        assembler.add_instruction(&xor_ebx_ebx);
        // 8b 2d ac 7d 00 00    	mov    ebp,DWORD PTR [rip+0x7dac]        # 0x7e5c
        try assembler.mov_ebp_dword_ptr(.dap_pointer);
        //b0:	66 8b 5d 2a          	mov    bx,WORD PTR [rbp+0x2a]
        assembler.add_instruction(&.{ 0x66, 0x8b, 0x5d, 0x2a });
        //b4:	66 8b 45 2c          	mov    ax,WORD PTR [rbp+0x2c]
        assembler.add_instruction(&.{ 0x66, 0x8b, 0x45, 0x2c });
        //b8:	8b 55 1c             	mov    edx,DWORD PTR [rbp+0x1c]
        assembler.add_instruction(&.{ 0x8b, 0x55, 0x1c });
        //bb:	01 ea                	add    edx,ebp
        assembler.add_instruction(&.{ 0x01, 0xea });
        //bd:	83 3a 01             	cmp    DWORD PTR [rdx],0x1
        try assembler.add_instruction_with_label(&.{ 0x83, 0x3a, 0x01 }, .elf_loader_loop);
        //c0:	75 0d                	jne    0xcf
        try assembler.jcc(jne, .elf_loader_loop_continue);
        //c2:	89 ee                	mov    esi,ebp
        assembler.add_instruction(&.{ 0x89, 0xee });
        //c4:	03 72 04             	add    esi,DWORD PTR [rdx+0x4]
        assembler.add_instruction(&.{ 0x03, 0x72, 0x04 });
        //c7:	8b 7a 0c             	mov    edi,DWORD PTR [rdx+0xc]
        assembler.add_instruction(&.{ 0x8b, 0x7a, 0x0c });
        //ca:	8b 4a 10             	mov    ecx,DWORD PTR [rdx+0x10]
        assembler.add_instruction(&.{ 0x8b, 0x4a, 0x10 });
        //cd:	f3 a4                	rep movs BYTE PTR es:[rdi],BYTE PTR ds:[rsi]
        assembler.add_instruction(&.{ 0xf3, 0xa4 });
        //cf:	01 da                	add    edx,ebx
        try assembler.add_instruction_with_label(&.{ 0x01, 0xda }, .elf_loader_loop_continue);
        //d1:	48                      dec    eax
        assembler.add_instruction(&.{0x48});
        // jnz loop
        const jnz = jne;
        try assembler.jcc(jnz, .elf_loader_loop);
        //d5:	8b 5d 18             	mov    ebx,DWORD PTR [rbp+0x18]
        assembler.add_instruction(&.{ 0x8b, 0x5d, 0x18 });
        //d8:	ff e3                	jmp    rbx
        assembler.add_instruction(&.{ 0xff, 0xe3 });
        log.debug("MBR code length: 0x{x}/0x{x}", .{ assembler.code_index, assembler.boot_disk.code.len });
    }

    const Label = enum {
        reload_cs_16,
        error16,
        read_sectors,
        dap,
        dap_pointer,
        gdt,
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

        pub inline fn add_instruction(assembler: *Assembler, instruction_bytes: []const u8) void {
            assert(assembler.code_index + instruction_bytes.len <= assembler.boot_disk.code.len);
            lib.print("[0x{x:0>4}] ", .{mbr_offset + @offsetOf(BootDisk, "code") + assembler.code_index});
            for (instruction_bytes) |byte| {
                lib.print("{x:0>2} ", .{byte});
            }
            lib.print("\n", .{});
            lib.copy(u8, assembler.boot_disk.code[assembler.code_index .. assembler.code_index + instruction_bytes.len], instruction_bytes);
            assembler.code_index += @intCast(u8, instruction_bytes.len);
        }

        pub fn add_instruction_with_label(assembler: *Assembler, instruction_bytes: []const u8, label: Label) !void {
            try assembler.labels.append(.{ .label = label, .offset = assembler.code_index });
            assembler.add_instruction(instruction_bytes);
        }

        pub fn far_jmp_16(assembler: *Assembler, segment: u16, label: Label) !void {
            const segment_bytes = lib.asBytes(&segment);
            const offset_bytes = lib.asBytes(&mbr_offset);
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
            assembler.add_instruction(&instruction_bytes);
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
            assembler.add_instruction(&instruction_bytes);
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
            assembler.add_instruction(&instruction_bytes);
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
            assembler.add_instruction(&instruction_bytes);
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
            assembler.add_instruction(&instruction_bytes);
        }

        pub fn patch(assembler: *Assembler) void {
            var patched: usize = 0;

            next_patch: for (assembler.patches.items) |patch_descriptor| {
                const index = patch_descriptor.instruction_starting_offset + patch_descriptor.label_offset;
                log.debug("Trying to patch instruction. Section: {s}. Label: {s}. Label size: {}. Label type: {s}", .{ @tagName(patch_descriptor.label_section), @tagName(patch_descriptor.label), patch_descriptor.label_size, @tagName(patch_descriptor.label_type) });
                switch (patch_descriptor.label_section) {
                    .code => for (assembler.labels.items) |label_descriptor| {
                        if (patch_descriptor.label == label_descriptor.label) {
                            switch (patch_descriptor.label_type) {
                                .absolute => {
                                    assert(patch_descriptor.label_size == @sizeOf(u16));
                                    @ptrCast(*align(1) u16, &assembler.boot_disk.code[index]).* = mbr_offset + @offsetOf(BootDisk, "code") + label_descriptor.offset;
                                },
                                .relative => {
                                    assert(patch_descriptor.label_size == @sizeOf(u8));
                                    assert(patch_descriptor.label_section == .code);
                                    const computed_after_instruction_offset = patch_descriptor.instruction_starting_offset + patch_descriptor.instruction_len;
                                    const operand_a = @intCast(isize, label_descriptor.offset);
                                    const operand_b = @intCast(isize, computed_after_instruction_offset);
                                    const diff = @bitCast(u8, @intCast(i8, operand_a - operand_b));
                                    log.debug("Operand A: 0x{x}. Operand B: 0x{x}. Result: 0x{x}", .{ operand_a, operand_b, diff });
                                    @ptrCast(*align(1) u8, &assembler.boot_disk.code[index]).* = diff;
                                },
                            }

                            const instruction_start = mbr_offset + @offsetOf(BootDisk, "code") + patch_descriptor.instruction_starting_offset;
                            lib.print("[0x{x:0>4}] ", .{instruction_start});
                            const instruction_bytes = assembler.boot_disk.code[patch_descriptor.instruction_starting_offset .. patch_descriptor.instruction_starting_offset + patch_descriptor.instruction_len];
                            for (instruction_bytes) |byte| {
                                lib.print("{x:0>2} ", .{byte});
                            }
                            lib.print("\n", .{});
                            patched += 1;
                            continue :next_patch;
                        }
                    },
                    .data => {
                        log.debug("Data: {s}", .{@tagName(patch_descriptor.label)});
                        const dap_offset = @offsetOf(BootDisk, "dap");
                        log.debug("DAP offset: 0x{x}", .{dap_offset});
                        switch (patch_descriptor.label_type) {
                            .absolute => {
                                assert(patch_descriptor.label_size == @sizeOf(u16));
                                const ptr = mbr_offset + @as(u16, switch (patch_descriptor.label) {
                                    .dap => dap_offset,
                                    .gdt => @offsetOf(BootDisk, "gdt_32"),
                                    .dap_pointer => dap_offset + @offsetOf(MBR.DAP, "offset"),
                                    else => @panic("wtF"),
                                });
                                log.debug("Ptr patched: 0x{x}", .{ptr});
                                @ptrCast(*align(1) u16, &assembler.boot_disk.code[index]).* = ptr;
                            },
                            .relative => @panic("wtF"),
                        }

                        log.debug("Patched instruction:", .{});
                        const instruction_start = mbr_offset + @offsetOf(BootDisk, "code") + patch_descriptor.instruction_starting_offset;
                        lib.print("[0x{x:0>4}] ", .{instruction_start});
                        const instruction_bytes = assembler.boot_disk.code[patch_descriptor.instruction_starting_offset .. patch_descriptor.instruction_starting_offset + patch_descriptor.instruction_len];
                        for (instruction_bytes) |byte| {
                            lib.print("{x:0>2} ", .{byte});
                        }
                        lib.print("\n", .{});

                        patched += 1;
                        continue :next_patch;
                    },
                }

                log.debug("Patch count: {}. Patched count: {}", .{ assembler.patches.items.len, patched });
                assert(patched == assembler.patches.items.len);
            }
        }
    };

    comptime {
        assert(@sizeOf(@This()) == 0x200);
    }
};

const Error = error{
    wrong_arguments,
    not_implemented,
};

pub fn main() anyerror!void {
    var arena_allocator = host.ArenaAllocator.init(host.page_allocator);
    defer arena_allocator.deinit();
    var wrapped_allocator = lib.Allocator.wrap(arena_allocator.allocator());

    const arguments = try @import("std").process.argsAlloc(wrapped_allocator.unwrap_zig());
    if (arguments.len != 4) {
        return Error.wrong_arguments;
    }

    const bootloader_id = lib.stringToEnum(lib.Bootloader, arguments[1]) orelse return Error.wrong_arguments;
    const architecture = lib.stringToEnum(lib.Target.Cpu.Arch, arguments[2]) orelse return Error.wrong_arguments;
    const boot_protocol = lib.stringToEnum(lib.Bootloader.Protocol, arguments[3]) orelse return Error.wrong_arguments;

    const suffix = try lib.concat(wrapped_allocator.unwrap_zig(), u8, &.{ "_", @tagName(bootloader_id), "_", @tagName(architecture), "_", @tagName(boot_protocol) });

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

            var files_parser = lib.FileParser.init(configuration_file);

            while (try files_parser.next()) |file_descriptor| {
                const host_relative_path = try lib.concat(wrapped_allocator.unwrap_zig(), u8, &.{ file_descriptor.host_path, "/", file_descriptor.host_base, switch (file_descriptor.suffix_type) {
                    .arch => switch (architecture) {
                        inline else => |arch| "_" ++ @tagName(arch),
                    },
                    .full => unreachable,
                    .none => unreachable,
                } });
                log.debug("Host relative path: {s}", .{host_relative_path});
                const file_content = try host.cwd().readFileAlloc(wrapped_allocator.unwrap_zig(), host_relative_path, max_file_length);
                try fat_partition_cache.create_file(file_descriptor.guest, file_content, wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));
            }

            blk: {
                const file_content = configuration_file;
                const guest_file_path = try lib.concat(wrapped_allocator.unwrap_zig(), u8, &.{ "/", config_file_name });
                try fat_partition_cache.create_file(guest_file_path, file_content, wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));
                break :blk;
            }

            switch (bootloader_id) {
                .limine => {
                    log.debug("Installing Limine HDD", .{});
                    try LimineInstaller.install(disk_image.get_buffer(), false, null);
                    log.debug("Ended installing Limine HDD", .{});
                    const limine_installable_path = "src/bootloader/limine/installables";
                    const limine_installable_dir = try host.cwd().openDir(limine_installable_path, .{});

                    const limine_cfg = try limine_installable_dir.readFileAlloc(wrapped_allocator.unwrap_zig(), "limine.cfg", max_file_length);
                    try fat_partition_cache.create_file("/limine.cfg", limine_cfg, wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));
                    const limine_sys = try limine_installable_dir.readFileAlloc(wrapped_allocator.unwrap_zig(), "limine.sys", max_file_length);
                    try fat_partition_cache.create_file("/limine.sys", limine_sys, wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));

                    switch (architecture) {
                        .x86_64 => {
                            try fat_partition_cache.make_new_directory("/BOOT", wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));
                            try fat_partition_cache.make_new_directory("/BOOT/EFI", wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));
                            try fat_partition_cache.create_file("/BOOT/EFI/BOOTX64.EFI", try limine_installable_dir.readFileAlloc(wrapped_allocator.unwrap_zig(), "BOOTX64.EFI", max_file_length), wrapped_allocator.unwrap(), null, @intCast(u64, host.time.milliTimestamp()));
                        },
                        else => unreachable,
                    }

                    // for (LimineInstaller.stage2) |b, i| {
                    //     const byte = disk_image.get_buffer()[i];
                    //     if (b != byte) {
                    //         log.debug("Byte 0x{x} modified. Original: 0x{x}. Have: 0x{x}", .{ i, b, byte });
                    //     }
                    // }
                },
                .rise => switch (boot_protocol) {
                    .bios => {
                        const loader_file_path = try lib.concat(wrapped_allocator.unwrap_zig(), u8, &.{ "zig-cache/", "loader", suffix });
                        log.debug("trying to load file: {s}", .{loader_file_path});
                        const loader_file = try host.cwd().readFileAlloc(wrapped_allocator.unwrap_zig(), loader_file_path, max_file_length);
                        const partition_first_usable_lba = gpt_partition_cache.gpt.header.first_usable_lba;
                        assert((fat_partition_cache.partition_range.first_lba - partition_first_usable_lba) * disk.sector_size > lib.alignForward(loader_file.len, disk.sector_size));
                        try disk.write_slice(u8, loader_file, partition_first_usable_lba, true);

                        // Build our own assembler
                        const boot_disk_mbr_lba = 0;
                        const boot_disk_mbr = try disk.read_typed_sectors(BootDisk, boot_disk_mbr_lba, null, .{});
                        const dap_offset = @offsetOf(BootDisk, "dap");
                        lib.log.debug("DAP offset: 0x{x}", .{dap_offset});
                        assert(dap_offset == 0x1ae);
                        const aligned_file_size = lib.alignForward(loader_file.len, 0x200);
                        const text_section_guess = lib.alignBackwardGeneric(u32, @ptrCast(*align(1) u32, &loader_file[0x18]).*, 0x1000);
                        if (lib.maxInt(u32) - text_section_guess < aligned_file_size) @panic("WTFFFF");
                        const dap_top = stack_top - stack_size;
                        if (aligned_file_size > dap_top) host.panic("File size: 0x{x} bytes", .{aligned_file_size});
                        log.debug("DAP top: 0x{x}. Aligned file size: 0x{x}", .{ dap_top, aligned_file_size });
                        const dap = MBR.DAP{
                            .sector_count = @intCast(u16, @divExact(aligned_file_size, disk.sector_size)),
                            .offset = @intCast(u16, dap_top - aligned_file_size),
                            .segment = 0x0,
                            .lba = partition_first_usable_lba,
                        };

                        if (dap_top - dap.offset < aligned_file_size) {
                            @panic("unable to fit file read from disk");
                        }

                        if (dap.offset - 0x600 < aligned_file_size) {
                            @panic("unable to fit loaded executable in memory");
                        }

                        try boot_disk_mbr.fill(wrapped_allocator.unwrap_zig(), dap);
                        try disk.write_typed_sectors(BootDisk, boot_disk_mbr, boot_disk_mbr_lba, false);
                    },
                    .uefi => @panic("rise uefi"),
                },
            }
        },
        else => @panic("Filesystem not supported"),
    }

    const disk_image_path = try lib.concat(wrapped_allocator.unwrap_zig(), u8, &.{ "zig-cache/", image_config.image_name });
    try host.cwd().writeFile(disk_image_path, disk_image.get_buffer());
}

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
        const mount_dir = partition.loopback_device.mount_dir orelse @panic("wtf");
        return mount_dir;
    }

    fn copy_file(partition: MountedPartition, allocator: lib.ZigAllocator, file_path: []const u8, file_content: []const u8) !void {
        const last_slash_index = lib.lastIndexOf(u8, file_path, "/") orelse @panic("wtf");
        const file_name = file_path[last_slash_index + 1 ..];
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
        const mount_dir = partition.loopback_device.mount_dir orelse @panic("wtf");
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

const ImageDescription = struct {
    partition_name: []const u8,
    partition_start_lba: u64,
    disk_sector_count: u64,
    disk_sector_size: u64,
    partition_filesystem: lib.FilesystemType,
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
        return try DiskImage.fromFile(image.path, @intCast(u16, image.description.disk_sector_size), allocator);
    }

    fn delete(image: ShellImage) !void {
        try host.cwd().deleteFile(image.path);
    }
};

const DiskImage = extern struct {
    disk: Disk,
    buffer_ptr: [*]u8,

    const File = struct {
        handle: lib.File,
        size: usize,
    };

    pub inline fn get_buffer(disk_image: DiskImage) []u8 {
        return disk_image.buffer_ptr[0..disk_image.disk.disk_size];
    }

    pub fn read(disk: *Disk, sector_count: u64, sector_offset: u64, provided_buffer: ?[]const u8) Disk.ReadError!Disk.ReadResult {
        assert(provided_buffer == null);
        const disk_image = @fieldParentPtr(DiskImage, "disk", disk);
        assert(disk_image.disk.disk_size > 0);
        assert(sector_count > 0);
        //assert(disk.disk.disk_size == disk.buffer.items.len);
        const byte_count = sector_count * disk_image.disk.sector_size;
        const byte_offset = sector_offset * disk_image.disk.sector_size;
        if (byte_offset + byte_count > disk.disk_size) {
            return Disk.ReadError.read_error;
        }
        return .{
            .buffer = disk_image.get_buffer()[byte_offset .. byte_offset + byte_count].ptr,
            .sector_count = sector_count,
        };
    }

    pub fn fromZero(sector_count: usize, sector_size: u16) !DiskImage {
        const disk_bytes = try host.allocateZeroMemory(sector_count * sector_size);
        var disk_image = DiskImage{
            .disk = .{
                .type = .memory,
                .callbacks = .{
                    .read = DiskImage.read,
                    .write = DiskImage.write,
                },
                .disk_size = disk_bytes.len,
                .sector_size = sector_size,
            },
            .buffer_ptr = disk_bytes.ptr,
        };

        return disk_image;
    }

    pub fn createFAT(disk_image: *DiskImage, comptime image: ImageDescription, original_gpt_cache: ?GPT.Partition.Cache) !GPT.Partition.Cache {
        const gpt_cache = try GPT.create(&disk_image.disk, if (original_gpt_cache) |o_gpt_cache| o_gpt_cache.gpt.header else null);
        const partition_name_u16 = lib.unicode.utf8ToUtf16LeStringLiteral(image.partition_name);
        const gpt_partition_cache = try gpt_cache.addPartition(image.partition_filesystem, partition_name_u16, image.partition_start_lba, gpt_cache.header.last_usable_lba, if (original_gpt_cache) |o_gpt_cache| o_gpt_cache.partition else null);

        return gpt_partition_cache;
    }

    pub fn fromFile(file_path: []const u8, sector_size: u16, allocator: lib.ZigAllocator) !DiskImage {
        const disk_memory = try host.cwd().readFileAlloc(allocator, file_path, lib.maxInt(usize));

        var disk_image = DiskImage{
            .disk = .{
                .type = .memory,
                .callbacks = .{
                    .read = DiskImage.read,
                    .write = DiskImage.write,
                },
                .disk_size = disk_memory.len,
                .sector_size = sector_size,
            },
            .buffer_ptr = disk_memory.ptr,
        };

        return disk_image;
    }

    pub fn write(disk: *Disk, bytes: []const u8, sector_offset: u64, commit_memory_to_disk: bool) Disk.WriteError!void {
        const need_write = !(disk.type == .memory and !commit_memory_to_disk);
        if (need_write) {
            const disk_image = @fieldParentPtr(DiskImage, "disk", disk);
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

fn cdiv(a: u32, b: u32) u32 {
    return (a + b - 1) / b;
}

pub fn format(disk: *Disk, partition_range: Disk.PartitionRange, copy_mbr: ?*const MBR.Partition) !FAT32.Cache {
    if (disk.type != .memory) @panic("disk is not memory");
    const fat_partition_mbr_lba = partition_range.first_lba;
    const fat_partition_mbr = try disk.read_typed_sectors(MBR.Partition, fat_partition_mbr_lba, null, .{});

    const sectors_per_track = 32;
    const total_sector_count_32 = @intCast(u32, lib.alignBackward(partition_range.last_lba - partition_range.first_lba, sectors_per_track));
    const fat_count = FAT32.count;

    var cluster_size: u8 = 1;
    const max_cluster_size = 128;
    var fat_data_sector_count: u32 = undefined;
    var fat_length_32: u32 = undefined;
    var cluster_count_32: u32 = undefined;

    while (true) {
        assert(cluster_size > 0);
        fat_data_sector_count = total_sector_count_32 - lib.alignForwardGeneric(u32, FAT32.default_reserved_sector_count, cluster_size);
        cluster_count_32 = (fat_data_sector_count * disk.sector_size + fat_count * 8) / (cluster_size * disk.sector_size + fat_count * 4);
        fat_length_32 = lib.alignForwardGeneric(u32, cdiv((cluster_count_32 + 2) * 4, disk.sector_size), cluster_size);
        cluster_count_32 = (fat_data_sector_count - fat_count * fat_length_32) / cluster_size;
        const max_cluster_size_32 = @min(fat_length_32 * disk.sector_size / 4, FAT32.getMaxCluster(.fat32));
        if (cluster_count_32 > max_cluster_size_32) {
            cluster_count_32 = 0;
        }
        if (cluster_count_32 != 0 and cluster_count_32 < FAT32.getMinCluster(.fat32)) {
            cluster_count_32 = 0;
        }

        if (cluster_count_32 != 0) break;

        cluster_size <<= 1;

        const keep_going = cluster_size != 0 and cluster_size <= max_cluster_size;
        if (!keep_going) break;
        @panic("wtf");
    }

    var root_directory_entries: u64 = 0;
    _ = root_directory_entries;

    const reserved_sector_count = lib.alignForwardGeneric(u16, FAT32.default_reserved_sector_count, cluster_size);

    fat_partition_mbr.* = MBR.Partition{
        .bpb = .{
            .dos3_31 = .{
                .dos2_0 = .{
                    .jmp_code = .{ 0xeb, 0x58, 0x90 },
                    .oem_identifier = "mkfs.fat".*,
                    .sector_size = disk.sector_size,
                    .cluster_sector_count = cluster_size,
                    .reserved_sector_count = reserved_sector_count,
                    .fat_count = fat_count,
                    .root_entry_count = 0,
                    .total_sector_count_16 = 0,
                    .media_descriptor = 0xf8,
                    .fat_sector_count_16 = 0,
                },
                .physical_sectors_per_track = sectors_per_track,
                .disk_head_count = 8,
                .hidden_sector_count = @intCast(u32, partition_range.first_lba),
                .total_sector_count_32 = total_sector_count_32,
            },
            .fat_sector_count_32 = fat_length_32,
            .drive_description = 0,
            .version = .{ 0, 0 },
            .root_directory_cluster_offset = FAT32.starting_cluster,
            .fs_info_sector = FAT32.default_fs_info_sector,
            .backup_boot_record_sector = FAT32.default_backup_boot_record_sector,
            .drive_number = 0x80,
            .extended_boot_signature = 0x29,
            .serial_number = if (copy_mbr) |copy_partition_mbr| copy_partition_mbr.bpb.serial_number else @truncate(u32, @intCast(u64, host.time.microTimestamp())),
            .volume_label = "NO NAME    ".*,
            .filesystem_type = "FAT32   ".*,
        },
        .code = [_]u8{
            0xe, 0x1f, 0xbe, 0x77, 0x7c, 0xac, 0x22, 0xc0, 0x74, 0xb, 0x56, 0xb4, 0xe, 0xbb, 0x7, 0x0, 0xcd, 0x10, 0x5e, 0xeb, 0xf0, 0x32, 0xe4, 0xcd, 0x16, 0xcd, 0x19, 0xeb, 0xfe, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x61, 0x20, 0x62, 0x6f, 0x6f, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x64, 0x69, 0x73, 0x6b, 0x2e, 0x20, 0x20, 0x50, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x20, 0x69, 0x6e, 0x73, 0x65, 0x72, 0x74, 0x20, 0x61, 0x20, 0x62, 0x6f, 0x6f, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x66, 0x6c, 0x6f, 0x70, 0x70, 0x79, 0x20, 0x61, 0x6e, 0x64, 0xd, 0xa, 0x70, 0x72, 0x65, 0x73, 0x73, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x74, 0x6f, 0x20, 0x74, 0x72, 0x79, 0x20, 0x61, 0x67, 0x61, 0x69, 0x6e, 0x20, 0x2e, 0x2e, 0x2e, 0x20, 0xd, 0xa,
        } ++ [1]u8{0} ** 227,
        // This should be zero
        .partitions = lib.zeroes([4]MBR.LegacyPartition),
    };

    try disk.write_typed_sectors(MBR.Partition, fat_partition_mbr, fat_partition_mbr_lba, false);

    const backup_boot_record_sector = partition_range.first_lba + fat_partition_mbr.bpb.backup_boot_record_sector;
    const backup_boot_record = try disk.read_typed_sectors(MBR.Partition, backup_boot_record_sector, null, .{});
    backup_boot_record.* = fat_partition_mbr.*;
    try disk.write_typed_sectors(MBR.Partition, backup_boot_record, backup_boot_record_sector, false);

    const fs_info_lba = partition_range.first_lba + fat_partition_mbr.bpb.fs_info_sector;
    const fs_info = try disk.read_typed_sectors(FAT32.FSInfo, fs_info_lba, null, .{});
    fs_info.* = .{
        .lead_signature = 0x41615252,
        .signature = 0x61417272,
        .free_cluster_count = cluster_count_32,
        .last_allocated_cluster = 0,
        .trail_signature = 0xaa550000,
    };
    try disk.write_typed_sectors(FAT32.FSInfo, fs_info, fs_info_lba, false);

    const cache = FAT32.Cache{
        .disk = disk,
        .partition_range = partition_range,
        .mbr = fat_partition_mbr,
        .fs_info = fs_info,
    };

    // TODO: write this properly

    try cache.registerCluster(0, FAT32.Entry.reserved_and_should_not_be_used_eof, null);
    try cache.registerCluster(1, FAT32.Entry.allocated_and_eof, null);
    try cache.registerCluster(2, FAT32.Entry.reserved_and_should_not_be_used_eof, null);

    cache.fs_info.last_allocated_cluster = 2;
    cache.fs_info.free_cluster_count = cluster_count_32 - 1;

    const backup_fs_info_lba = backup_boot_record_sector + backup_boot_record.bpb.fs_info_sector;
    const backup_fs_info = try disk.read_typed_sectors(FAT32.FSInfo, backup_fs_info_lba, null, .{});
    backup_fs_info.* = fs_info.*;
    try disk.write_typed_sectors(FAT32.FSInfo, backup_fs_info, backup_fs_info_lba, false);

    return cache;
}

// test "Basic FAT32 image" {
//     lib.testing.log_level = .debug;
//
//     switch (lib.os) {
//         .linux => {
//             const original_image_path = "barebones.hdd";
//             const sector_count = 131072;
//             const sector_size = 0x200;
//             const partition_start_lba = 0x800;
//             const partition_name = "ESP";
//             const partition_filesystem = lib.Filesystem.Type.fat32;
//
//             // Using an arena allocator because it doesn't care about memory leaks
//             var arena_allocator = host.ArenaAllocator.init(host.page_allocator);
//             defer arena_allocator.deinit();
//
//             var wrapped_allocator = lib.Allocator.wrap(arena_allocator.allocator());
//
//             var disk_image = try DiskImage.fromZero(sector_count, sector_size);
//             defer host.cwd().deleteFile(original_image_path) catch @panic("wtf");
//
//             const directories = [_][]const u8{ "/EFI", "/EFI/BOOT", "/EFI/BOOT/FOO" };
//             const files = [_]struct { path: []const u8, content: []const u8 }{
//                 .{ .path = "/foo", .content = "this is the foo file content" },
//                 .{ .path = "/EFI/def", .content = "this is the def file content" },
//                 .{ .path = "/EFI/BOOT/xyz", .content = "this is the xyz file content" },
//                 .{ .path = "/EFI/opq", .content = "this is the opq file content" },
//             };
//
//             // 1. Test GPT creation
//             var original_disk_image = blk: {
//                 const megabytes = @divExact(sector_count * sector_size, lib.mb);
//                 try host.spawnProcess(&.{ "dd", "if=/dev/zero", "bs=1M", "count=0", try lib.allocPrint(wrapped_allocator.unwrap_zig(), "seek={d}", .{megabytes}), try lib.allocPrint(wrapped_allocator.unwrap_zig(), "of={s}", .{original_image_path}) }, wrapped_allocator.unwrap_zig());
//
//                 try host.spawnProcess(&.{ "parted", "-s", original_image_path, "mklabel", "gpt" }, wrapped_allocator.unwrap_zig());
//                 try host.spawnProcess(&.{ "parted", "-s", original_image_path, "mkpart", partition_name, @tagName(partition_filesystem), try lib.allocPrint(wrapped_allocator.unwrap_zig(), "{d}s", .{partition_start_lba}), "100%" }, wrapped_allocator.unwrap_zig());
//                 try host.spawnProcess(&.{ "parted", "-s", original_image_path, "set", "1", "esp", "on" }, wrapped_allocator.unwrap_zig());
//
//                 var loopback_device = LoopbackDevice{ .name = "loopback_device" };
//                 try loopback_device.start(wrapped_allocator.unwrap_zig(), original_image_path);
//
//                 try host.spawnProcess(&.{ "./tools/format_loopback_fat32.sh", loopback_device.name }, wrapped_allocator.unwrap_zig());
//
//                 const mount_dir = "image_mount";
//
//                 var partition = try loopback_device.mount(wrapped_allocator.unwrap_zig(), mount_dir);
//
//                 for (directories) |directory| {
//                     try partition.mkdir(wrapped_allocator.unwrap_zig(), directory);
//                 }
//
//                 for (files) |file| {
//                     try partition.copy_file(wrapped_allocator.unwrap_zig(), file.path, file.content);
//                 }
//
//                 try partition.end(wrapped_allocator.unwrap_zig());
//                 try partition.loopback_device.end(wrapped_allocator.unwrap_zig());
//
//                 break :blk try DiskImage.fromFile(original_image_path, sector_size, wrapped_allocator.unwrap_zig());
//             };
//
//             const original_gpt_cache = try GPT.Partition.Cache.fromPartitionIndex(&original_disk_image.disk, 0, wrapped_allocator.unwrap());
//             const original_fat_cache = try FAT32.Cache.fromGPTPartitionCache(wrapped_allocator.unwrap(), original_gpt_cache);
//
//             const gpt_cache = try GPT.create(&disk_image.disk, original_gpt_cache.gpt.header);
//             const gpt_partition_cache = try gpt_cache.addPartition(partition_filesystem, lib.unicode.utf8ToUtf16LeStringLiteral(partition_name), partition_start_lba, gpt_cache.header.last_usable_lba, original_gpt_cache.partition);
//             const fat_partition_cache = try format(gpt_partition_cache.gpt.disk, .{
//                 .first_lba = gpt_partition_cache.partition.first_lba,
//                 .last_lba = gpt_partition_cache.partition.last_lba,
//             }, original_fat_cache.mbr);
//
//             for (directories) |directory| {
//                 try fat_partition_cache.make_new_directory(directory, null, original_fat_cache, @intCast(u64, host.time.milliTimestamp()));
//             }
//
//             for (files) |file| {
//                 try fat_partition_cache.create_file(file.path, file.content, wrapped_allocator.unwrap(), original_fat_cache, @intCast(u64, host.time.milliTimestamp()));
//             }
//
//             try lib.diff(original_disk_image.get_buffer(), disk_image.get_buffer());
//             try lib.testing.expectEqualSlices(u8, original_disk_image.get_buffer(), disk_image.get_buffer());
//         },
//         else => {
//             //log.debug("Skipping for missing `parted` dependency...", .{}),
//         },
//     }
// }

extern fn deploy(device_path: [*:0]const u8, limine_hdd_ptr: [*]const u8, limine_hdd_len: usize) callconv(.C) c_int;

const File = struct {
    path: []const u8,
    content: []const u8,
};

const limine_directories = [_][]const u8{
    "/EFI", "/EFI/BOOT",
};
const limine_files = [_]File{
    // .{ .path = "/limine.sys", .content = @embedFile("bootloader/limine/installables/limine.sys") },
    // .{ .path = "/limine.cfg", .content = @embedFile("bootloader/limine/installables/limine.cfg") },
    .{ .path = "/limine.sys", .content = &[1]u8{0xff} ** 513 },
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
                .disk_sector_size = 0x200,
                .partition_name = "ESP",
                .partition_filesystem = .fat32,
            };

            const test_path = "zig-cache/test_original.hdd";
            const test_image = ShellImage{
                .path = test_path,
                .description = image,
            };
            test_image.delete() catch {};

            try test_image.createFAT(wrapped_allocator.unwrap_zig());
            if (deploy_limine and deploy(test_path, &LimineInstaller.hdd, LimineInstaller.hdd.len) != 0) {
                @panic("asjdkajsd");
            }

            var loopback_device = LoopbackDevice{ .name = "loopback_device" };
            try loopback_device.start(wrapped_allocator.unwrap_zig(), test_path);

            try host.spawnProcess(&.{ "./tools/format_loopback_fat32.sh", loopback_device.name }, wrapped_allocator.unwrap_zig());

            const mount_dir = "image_mount";

            var partition = try loopback_device.mount(wrapped_allocator.unwrap_zig(), mount_dir);

            for (limine_directories) |directory| {
                try partition.mkdir(wrapped_allocator.unwrap_zig(), directory);
            }

            for (limine_files) |file| {
                try partition.copy_file(wrapped_allocator.unwrap_zig(), file.path, file.content);
            }

            try partition.end(wrapped_allocator.unwrap_zig());
            try loopback_device.end(wrapped_allocator.unwrap_zig());

            var original_disk_image = try test_image.toDiskImage(wrapped_allocator.unwrap_zig());
            const original_gpt_cache = try GPT.Partition.Cache.fromPartitionIndex(&original_disk_image.disk, 0, wrapped_allocator.unwrap());
            const original_fat_cache = try FAT32.Cache.fromGPTPartitionCache(wrapped_allocator.unwrap(), original_gpt_cache);

            var disk_image = try DiskImage.fromZero(image.disk_sector_count, image.disk_sector_size);
            const gpt_partition_cache = try disk_image.createFAT(image, original_gpt_cache);

            const original_buffer = original_disk_image.get_buffer();
            const my_buffer = disk_image.get_buffer();

            if (deploy_limine) {
                try LimineInstaller.install(my_buffer, false, null);
            }

            const fat_partition_cache = try format(gpt_partition_cache.gpt.disk, .{
                .first_lba = gpt_partition_cache.partition.first_lba,
                .last_lba = gpt_partition_cache.partition.last_lba,
            }, original_fat_cache.mbr);

            for (limine_directories) |directory| {
                log.debug("Creating directory: {s}", .{directory});
                try fat_partition_cache.make_new_directory(directory, null, original_fat_cache, @intCast(u64, host.time.milliTimestamp()));
            }

            for (limine_files) |file| {
                log.debug("Creating file: {s}", .{file.path});
                try fat_partition_cache.create_file(file.path, file.content, wrapped_allocator.unwrap(), original_fat_cache, @intCast(u64, host.time.milliTimestamp()));
            }

            var diff_count: u32 = 0;
            for (my_buffer) |mb, i| {
                const ob = original_buffer[i];
                const diff = ob != mb;
                if (diff) {
                    log.debug("[0x{x}] Diff. Expected: 0x{x}. Actual: 0x{x}", .{ i, ob, mb });
                }
                diff_count += @boolToInt(diff);
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
