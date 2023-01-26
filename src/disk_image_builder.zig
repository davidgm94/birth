const host = @import("host.zig");
const lib = @import("lib.zig");

const assert = lib.assert;
const log = lib.log.scoped(.DiskImageBuilder);

const Disk = lib.Disk;
const GPT = lib.PartitionTable.GPT;
const MBR = lib.PartitionTable.MBR;

const max_file_length = lib.maxInt(usize);

const mbr_offset: u16 = 0xfe00;
const stack_top: u16 = mbr_offset;
const stack_size = 0x1000;

// TODO: introduce Limine in this executable

//const BootImage = struct {
//fn build(step: *host.build.Step) !void {
//const kernel = @fieldParentPtr(Kernel, "boot_image_step", step);

//switch (kernel.options.arch) {
//.x86_64 => {
//switch (kernel.options.arch.x86_64.bootloader) {
//.rise_uefi => {
//var cache_dir_handle = try std.fs.cwd().openDir(kernel.builder.cache_root, .{});
//defer cache_dir_handle.close();
//const img_dir_path = kernel.builder.fmt("{s}/img_dir", .{kernel.builder.cache_root});
//const current_directory = cwd();
//current_directory.deleteFile(Limine.image_path) catch {};
//const img_dir = try current_directory.makeOpenPath(img_dir_path, .{});
//const img_efi_dir = try img_dir.makeOpenPath("EFI/BOOT", .{});

//try Dir.copyFile(cache_dir_handle, "BOOTX64.efi", img_efi_dir, "BOOTX64.EFI", .{});
//try Dir.copyFile(cache_dir_handle, "kernel.elf", img_dir, "kernel.elf", .{});
//// TODO: copy all userspace programs
//try Dir.copyFile(cache_dir_handle, "init", img_dir, "init", .{});
//},
//.rise_bios => {},
//.limine => {
//const img_dir_path = kernel.builder.fmt("{s}/img_dir", .{kernel.builder.cache_root});
//const current_directory = cwd();
//current_directory.deleteFile(Limine.image_path) catch {};
//const img_dir = try current_directory.makeOpenPath(img_dir_path, .{});
//const img_efi_dir = try img_dir.makeOpenPath("EFI/BOOT", .{});

//const limine_dir = try current_directory.openDir(Limine.installables_path, .{});

//const limine_efi_bin_file = "limine-cd-efi.bin";
//const files_to_copy_from_limine_dir = [_][]const u8{
//"limine.cfg",
//"limine.sys",
//"limine-cd.bin",
//limine_efi_bin_file,
//};

//for (files_to_copy_from_limine_dir) |filename| {
//try Dir.copyFile(limine_dir, filename, img_dir, filename, .{});
//}
//try Dir.copyFile(limine_dir, "BOOTX64.EFI", img_efi_dir, "BOOTX64.EFI", .{});
//try Dir.copyFile(current_directory, kernel_path, img_dir, path.basename(kernel_path), .{});

//const xorriso_executable = switch (common.os) {
//.windows => "tools/xorriso-windows/xorriso.exe",
//else => "xorriso",
//};
//var xorriso_process = ChildProcess.init(&.{ xorriso_executable, "-as", "mkisofs", "-quiet", "-b", "limine-cd.bin", "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table", "--efi-boot", limine_efi_bin_file, "-efi-boot-part", "--efi-boot-image", "--protective-msdos-label", img_dir_path, "-o", Limine.image_path }, kernel.builder.allocator);
//// Ignore stderr and stdout
//xorriso_process.stdin_behavior = ChildProcess.StdIo.Ignore;
//xorriso_process.stdout_behavior = ChildProcess.StdIo.Ignore;
//xorriso_process.stderr_behavior = ChildProcess.StdIo.Ignore;
//_ = try xorriso_process.spawnAndWait();

//try Limine.installer.install(Limine.image_path, false, null);
//},
//}
//},
//else => unreachable,
//}
//}
//};

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

    const arguments = try host.std.process.argsAlloc(wrapped_allocator.unwrap_zig());
    if (arguments.len != 4) {
        return Error.wrong_arguments;
    }

    const bootloader = lib.stringToEnum(lib.Bootloader, arguments[1]) orelse return Error.wrong_arguments;
    const architecture = lib.stringToEnum(lib.Target.Cpu.Arch, arguments[2]) orelse return Error.wrong_arguments;
    const boot_protocol = lib.stringToEnum(lib.Bootloader.Protocol, arguments[3]) orelse return Error.wrong_arguments;

    const suffix = try lib.concat(wrapped_allocator.unwrap_zig(), u8, &.{ "_", @tagName(bootloader), "_", @tagName(architecture), "_", @tagName(boot_protocol) });

    // TODO: use a format with hex support
    const image_config = try host.ImageConfig.get(wrapped_allocator.unwrap_zig(), host.ImageConfig.default_path);
    var disk_image = try Disk.Image.fromZero(image_config.sector_count, image_config.sector_size);
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
            const fat_partition_cache = try gpt_partition_cache.format(filesystem, null);

            var files_parser = lib.FileParser.init(configuration_file);

            while (try files_parser.next()) |file_descriptor| {
                const host_relative_path = try host.concat(wrapped_allocator.unwrap_zig(), u8, &.{ file_descriptor.host_path, "/", file_descriptor.host_base, switch (file_descriptor.suffix_type) {
                    .arch => switch (architecture) {
                        inline else => |arch| "_" ++ @tagName(arch),
                    },
                    .full => unreachable,
                    .none => unreachable,
                } });
                log.debug("Host relative path: {s}", .{host_relative_path});
                const file_content = try host.cwd().readFileAlloc(wrapped_allocator.unwrap_zig(), host_relative_path, max_file_length);
                try fat_partition_cache.create_file(file_descriptor.guest, file_content, wrapped_allocator.unwrap(), null);
            }

            blk: {
                const file_content = configuration_file;
                const guest_file_path = try lib.concat(wrapped_allocator.unwrap_zig(), u8, &.{ "/", config_file_name });
                try fat_partition_cache.create_file(guest_file_path, file_content, wrapped_allocator.unwrap(), null);
                break :blk;
            }

            const loader_file = try host.cwd().readFileAlloc(wrapped_allocator.unwrap_zig(), try host.concat(wrapped_allocator.unwrap_zig(), u8, &.{ "zig-cache/", "loader", suffix }), max_file_length);
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
            if (aligned_file_size > dap_top) @panic("File too big");
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
        else => @panic("Filesystem not supported"),
    }

    const disk_image_path = try host.concat(wrapped_allocator.unwrap_zig(), u8, &.{ "zig-cache/", image_config.image_name });
    try host.cwd().writeFile(disk_image_path, disk_image.get_buffer());
}
