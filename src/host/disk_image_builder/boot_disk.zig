const bootloader = @import("bootloader");
const bios = @import("bios");
const uefi = @import("uefi");
const host = @import("host");
const lib = @import("lib");
const assert = lib.assert;
const MBR = lib.PartitionTable.MBR;

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
    const mov_sp_stack_top = [_]u8{0xbc} ++ lib.asBytes(&bios.stack_top).*;
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
            .address = bios.mbr_offset + @offsetOf(BootDisk, "gdt"),
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
        assembler.addInstruction(&mov_di(bios.mbr_offset));
        assembler.addInstruction(&mov_cx(lib.default_sector_size));
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
        const aligned_file_size = @as(u32, dap.sector_count * lib.default_sector_size);
        assembler.addInstruction(&[_]u8{0xb9} ++ lib.asBytes(&aligned_file_size));
        assembler.addInstruction(&cld);
        assembler.addInstruction(&[_]u8{ 0xf3, 0xa4 });

        // mov ebp, 0x10000
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

        // EXPERIMENT: stack to a higher address
        assembler.addInstruction(.{@as(u8, 0xbd)} ++ lib.asBytes(&bios.loader_stack_top));

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
            // lib.print("[0x{x:0>4}] ", .{bios.mbr_offset + @offsetOf(BootDisk, "code") + assembler.code_index});
            // for (instruction_bytes) |byte| {
            //     lib.print("{x:0>2} ", .{byte});
            // }
            // lib.print("\n", .{});
            @memcpy(assembler.boot_disk.code[assembler.code_index .. assembler.code_index + instruction_bytes.len], instruction_bytes);
            assembler.code_index += @as(u8, @intCast(instruction_bytes.len));
        }

        pub fn add_instruction_with_label(assembler: *Assembler, instruction_bytes: []const u8, label: Label) !void {
            try assembler.labels.append(.{ .label = label, .offset = assembler.code_index });
            assembler.addInstruction(instruction_bytes);
        }

        pub fn far_jmp_16(assembler: *Assembler, segment: u16, label: Label) !void {
            const segment_bytes = lib.asBytes(&segment);
            const offset_bytes = lib.asBytes(&bios.mbr_offset);
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
                                    @as(*align(1) u16, @ptrCast(&assembler.boot_disk.code[index])).* = bios.mbr_offset + @offsetOf(BootDisk, "code") + label_descriptor.offset;
                                },
                                .relative => {
                                    assert(patch_descriptor.label_size == @sizeOf(u8));
                                    assert(patch_descriptor.label_section == .code);
                                    const computed_after_instruction_offset = patch_descriptor.instruction_starting_offset + patch_descriptor.instruction_len;
                                    const operand_a = @as(isize, @intCast(label_descriptor.offset));
                                    const operand_b = @as(isize, @intCast(computed_after_instruction_offset));
                                    const diff = @as(u8, @bitCast(@as(i8, @intCast(operand_a - operand_b))));
                                    @as(*align(1) u8, @ptrCast(&assembler.boot_disk.code[index])).* = diff;
                                },
                            }

                            // const instruction_start = bios.mbr_offset + @offsetOf(BootDisk, "code") + patch_descriptor.instruction_starting_offset;
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
                                const ptr = bios.mbr_offset + @as(u16, switch (patch_descriptor.label) {
                                    .dap => dap_offset,
                                    .gdt_descriptor => @offsetOf(BootDisk, "gdt_descriptor"),
                                    .dap_pointer => dap_offset + @offsetOf(MBR.DAP, "offset"),
                                    else => @panic("unreachable tag"),
                                });
                                // log.debug("Ptr patched: 0x{x}", .{ptr});
                                @as(*align(1) u16, @ptrCast(&assembler.boot_disk.code[index])).* = ptr;
                            },
                            .relative => @panic("unreachable relative"),
                        }

                        // log.debug("Patched instruction:", .{});
                        // const instruction_start = bios.mbr_offset + @offsetOf(BootDisk, "code") + patch_descriptor.instruction_starting_offset;
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
        assert(@sizeOf(@This()) == lib.default_sector_size);
    }
};
