const lib = @import("../lib.zig");
const assert = lib.assert;
const bootloader = @import("../bootloader.zig");

const privileged = @import("../privileged.zig");
const ACPI = privileged.ACPI;
const x86_64 = privileged.arch.x86_64;
const PhysicalAddress = x86_64.PhysicalAddress;
const VirtualAddress = x86_64.VirtualAddress;
const PhysicalMemoryRegion = x86_64.PhysicalMemoryRegion;
const VirtualMemoryRegion = x86_64.VirtualMemoryRegion;
const PhysicalAddressSpace = x86_64.PhysicalAddressSpace;
const VirtualAddressSpace = x86_64.VirtualAddressSpace;

inline fn segment(value: u32) u16 {
    return @intCast(u16, value & 0xffff0) >> 4;
}

inline fn offset(value: u32) u16 {
    return @truncate(u16, value & 0xf >> 0);
}

pub const Disk = extern struct {
    disk: lib.Disk,

    var buffer = [1]u8{0} ** (0x200 * 0x4);

    pub fn read(disk: *lib.Disk, sector_count: u64, sector_offset: u64, maybe_provided_buffer: ?[]u8) lib.Disk.ReadError!lib.Disk.ReadResult {
        const provided_buffer = maybe_provided_buffer orelse @panic("buffer was not provided");
        if (sector_count > lib.maxInt(u16)) @panic("too many sectors");

        const disk_buffer_address = @ptrToInt(&buffer);
        if (disk_buffer_address > lib.maxInt(u16)) @panic("address too high");

        var sectors_left = sector_count;
        while (sectors_left > 0) {
            const buffer_sectors = @divExact(buffer.len, disk.sector_size);
            const sectors_to_read = @intCast(u16, @min(sectors_left, buffer_sectors));
            defer sectors_left -= sectors_to_read;

            const lba_offset = sector_count - sectors_left;
            const lba = sector_offset + lba_offset;

            const dap = DAP{
                .sector_count = sectors_to_read,
                .offset = @intCast(u16, disk_buffer_address),
                .segment = 0,
                .lba = lba,
            };

            const dap_address = @ptrToInt(&dap);
            const dap_offset = offset(dap_address);
            const dap_segment = segment(dap_address);
            var registers = Registers{
                .eax = 0x4200,
                .edx = 0x80,
                .esi = dap_offset,
                .ds = dap_segment,
            };

            interrupt(0x13, &registers, &registers);
            if (registers.eflags.flags.carry_flag) @panic("disk read failed");
            const provided_buffer_offset = lba_offset * disk.sector_size;
            const bytes_to_copy = sectors_to_read * disk.sector_size;
            const dst_slice = provided_buffer[@intCast(usize, provided_buffer_offset)..];
            const src_slice = buffer[0..bytes_to_copy];
            lib.copy(u8, dst_slice, src_slice);
        }

        const result = lib.Disk.ReadResult{
            .sector_count = sector_count,
            .buffer = provided_buffer.ptr,
        };

        return result;
    }

    pub fn write(disk: *lib.Disk, bytes: []const u8, sector_offset: u64, commit_memory_to_disk: bool) lib.Disk.WriteError!void {
        _ = disk;
        _ = bytes;
        _ = sector_offset;
        _ = commit_memory_to_disk;
        @panic("todo: disk write");
    }
};

extern fn interrupt(number: u8, out_regs: *Registers, in_regs: *const Registers) callconv(.C) void;

const DAP = lib.PartitionTable.MBR.DAP;

const Registers = extern struct {
    gs: u16 = 0,
    fs: u16 = 0,
    es: u16 = 0,
    ds: u16 = 0,
    eflags: packed struct(u32) {
        flags: packed struct(u16) {
            carry_flag: bool = false,
            reserved: u1 = 1,
            parity_flag: bool = false,
            reserved1: u1 = 0,
            adjust_flag: bool = false,
            reserved2: u1 = 0,
            zero_flag: bool = false,
            sign_flag: bool = false,
            trap_flag: bool = false,
            interrupt_enabled_flag: bool = false,
            direction_flag: bool = false,
            overflow_flag: bool = false,
            io_privilege_level: u2 = 0,
            nested_task_flag: bool = false,
            mode_flag: bool = false,
        } = .{},
        extended: packed struct(u16) {
            resume_flag: bool = false,
            virtual_8086_mode: bool = false,
            alignment_smap_check: bool = false,
            virtual_interrupt_flag: bool = false,
            virtual_interrupt_pending: bool = false,
            cpuid: bool = false,
            reserved: u8 = 0,
            aes_key_schedule: bool = false,
            reserved1: bool = false,
        } = .{},
    } = .{},
    ebp: u32 = 0,
    edi: u32 = 0,
    esi: u32 = 0,
    edx: u32 = 0,
    ecx: u32 = 0,
    ebx: u32 = 0,
    eax: u32 = 0,
};

fn A20IsEnabled() bool {
    const address = 0x7dfe;
    const address_with_offset = address + 0x100000;
    if (@intToPtr(*volatile u16, address).* != @intToPtr(*volatile u16, address_with_offset).*) {
        return true;
    }

    @intToPtr(*volatile u16, address).* = ~(@intToPtr(*volatile u16, address).*);

    if (@intToPtr(*volatile u16, address).* != @intToPtr(*volatile u16, address_with_offset).*) {
        return true;
    }

    return false;
}

const A20Error = error{a20_not_enabled};

pub fn A20Enable() A20Error!void {
    if (!A20IsEnabled()) {
        return A20Error.a20_not_enabled;
    }
    // TODO:
}

pub const MemoryMapEntry = extern struct {
    region: PhysicalMemoryRegion(.global),
    type: Type,
    unused: u32 = 0,

    pub inline fn isUsable(entry: MemoryMapEntry) bool {
        return entry.type == .usable and entry.region.address.value() >= lib.mb;
    }

    const Type = enum(u32) {
        usable = 1,
        reserved = 2,
        acpi_reclaimable = 3,
        acpi_nvs = 4,
        bad_memory = 5,
    };
};

var memory_map_entries: [max_memory_entry_count]MemoryMapEntry = undefined;
const max_memory_entry_count = 32;

pub const E820Iterator = extern struct {
    registers: Registers = .{},
    index: u32 = 0,

    pub fn next(iterator: *E820Iterator) ?struct { descriptor: MemoryMapEntry, index: usize } {
        var memory_map_entry: MemoryMapEntry = undefined;

        comptime assert(@sizeOf(MemoryMapEntry) == 24);
        iterator.registers.eax = 0xe820;
        iterator.registers.ecx = @sizeOf(MemoryMapEntry);
        iterator.registers.edx = 0x534d4150;
        iterator.registers.edi = @ptrToInt(&memory_map_entry);

        interrupt(0x15, &iterator.registers, &iterator.registers);

        if (!iterator.registers.eflags.flags.carry_flag and iterator.registers.ebx != 0) {
            const entry_index = iterator.index;
            iterator.index += 1;
            return .{ .index = entry_index, .descriptor = memory_map_entry };
        } else {
            return null;
        }
    }
};

pub fn getMemoryMapEntryCount() u32 {
    var entry_count: u32 = 0;
    var iterator = E820Iterator{};

    while (iterator.next()) |_| {
        entry_count += 1;
    }

    return entry_count;
}

const SuitableEntry = extern struct {
    region: PhysicalMemoryRegion(.local),
    index: u32,
};

pub fn fetchMemoryEntries(memory_map: []bootloader.MemoryMapEntry) void {
    var iterator = E820Iterator{};
    while (iterator.next()) |entry| {
        memory_map[entry.index] = .{
            .region = entry.descriptor.region,
            .type = switch (entry.descriptor.type) {
                .usable => if (entry.descriptor.isUsable()) .usable else .reserved,
                .bad_memory => .bad_memory,
                else => .reserved,
            },
        };
    }

    if (iterator.index != memory_map.len) @panic("Memory map entries don't match");
}

const FindRSDPResult = union(enum) {
    descriptor1: *ACPI.RSDP.Descriptor1,
    descriptor2: *ACPI.RSDP.Descriptor2,
};

fn wrapSumBytes(bytes: []const u8) u8 {
    var result: u8 = 0;
    for (bytes) |byte| {
        result +%= byte;
    }
    return result;
}

pub fn getEBDAAddress() u32 {
    const expected_EBDA_base = 0x80000;
    const expected_EBDA_top = 0xa0000;

    const base = @as(u32, @intToPtr(*u16, 0x40e).*) << 4;

    if (base < expected_EBDA_base or base > expected_EBDA_top) {
        return expected_EBDA_base;
    } else {
        return base;
    }
}

pub fn findRSDP() ?u32 {
    const ebda_address = getEBDAAddress();
    const main_bios_area_base_address = 0xe0000;
    const RSDP_PTR = "RSD PTR ".*;

    const pointers = [2]u32{ ebda_address, main_bios_area_base_address };
    const limits = [2]u32{ ebda_address + @intCast(u32, @enumToInt(lib.SizeUnit.kilobyte)), @intCast(u32, @enumToInt(lib.SizeUnit.megabyte)) };
    for (pointers) |pointer, index| {
        var ptr = pointer;
        const limit = limits[index];

        while (ptr < limit) : (ptr += 16) {
            const rsdp_descriptor = @intToPtr(*ACPI.RSDP.Descriptor1, ptr);
            if (lib.equal(u8, &rsdp_descriptor.signature, &RSDP_PTR)) {
                switch (rsdp_descriptor.revision) {
                    0 => if (wrapSumBytes(lib.asBytes(rsdp_descriptor)) == 0) return @ptrToInt(rsdp_descriptor),
                    2 => {
                        const rsdp_descriptor2 = @fieldParentPtr(ACPI.RSDP.Descriptor2, "descriptor1", rsdp_descriptor);
                        if (wrapSumBytes(lib.asBytes(rsdp_descriptor2)) == 0) return @ptrToInt(rsdp_descriptor);
                    },
                    else => unreachable,
                }
            }
        }
    }

    return null;
}

pub const RealModePointer = extern struct {
    offset: u16,
    segment: u16,

    pub inline fn desegment(real_mode_pointer: RealModePointer, comptime Ptr: type) Ptr {
        return @intToPtr(Ptr, (@as(u32, real_mode_pointer.segment) << 4) + real_mode_pointer.offset);
    }
};

pub const VBE = extern struct {
    pub const Information = extern struct {
        signature: [4]u8,
        version_minor: u8,
        version_major: u8,
        OEM: RealModePointer,
        capabitilies: [4]u8,
        video_modes: RealModePointer,
        video_memory_blocks: u16,
        OEM_software_revision: u16,
        OEM_vendor: RealModePointer,
        OEM_product_name: RealModePointer,
        OEM_product_revision: RealModePointer,
        reserved: [222]u8,
        OEM_data: [256]u8,

        pub const Capabilities = packed struct(u32) {
            dac_switchable: bool,
            controller_not_vga_compatible: bool,
            ramdac_blank: bool,
            hardware_stereoscopic_signaling: bool,
            VESA_EVC_stereo_signaling: bool,
            reserved: u27 = 0,
        };

        comptime {
            assert(@sizeOf(Information) == 0x200);
        }

        pub fn getVideoMode(vbe_info: *const VBE.Information, comptime isValidVideoMode: fn (mode: *const Mode) bool, desired_width: u16, desired_height: u16, edid_bpp: u8) ?Mode {
            const video_modes = vbe_info.video_modes.desegment([*]const u16);
            for (video_modes[0..lib.maxInt(usize)]) |video_mode_number| {
                if (video_mode_number == 0xffff) break;
                var registers = Registers{};
                var mode: VBE.Mode = undefined;

                registers.ecx = video_mode_number;
                registers.edi = @ptrToInt(&mode);

                VBEinterrupt(.get_mode_information, &registers) catch continue;

                if (isValidVideoMode(&mode) and mode.resolution_x == desired_width and mode.resolution_y == desired_height and mode.bpp == edid_bpp) {
                    lib.log.debug("Video mode setting", .{});
                    setVideoMode(video_mode_number) catch continue;
                    lib.log.debug("Video mode set", .{});
                    return mode;
                }
            }

            return null;
        }
    };

    pub const Mode = extern struct {
        mode_attributes: Attributes,
        wina_attributes: u8,
        winb_attributes: u8,
        win_granularity: u16,
        win_size: u16,
        wina_segment: u16,
        winb_segment: u16,
        win_far_pointer: u32 align(2),
        bytes_per_scanline: u16,

        resolution_x: u16,
        resolution_y: u16,
        character_size_x: u8,
        character_size_y: u8,
        plane_count: u8,
        bpp: u8,
        bank_count: u8,
        memory_model: MemoryModel,
        bank_size: u8,
        image_count: u8,
        reserved: u8 = 0,

        red_mask_size: u8,
        red_mask_shift: u8,
        green_mask_size: u8,
        green_mask_shift: u8,
        blue_mask_size: u8,
        blue_mask_shift: u8,
        reserved_mask_size: u8,
        reserved_mask_shift: u8,
        direct_color_info: u8,

        framebuffer_address: u32 align(2),
        reserved_arr: [6]u8,

        linear_bytes_per_scanline: u16,
        banked_image_count: u8,
        linear_image_count: u8,
        linear_red_mask_size: u8,
        linear_red_mask_shift: u8,
        linear_green_mask_size: u8,
        linear_green_mask_shift: u8,
        linear_blue_mask_size: u8,
        linear_blue_mask_shift: u8,
        linear_reserved_mask_size: u8,
        linear_reserved_mask_shift: u8,
        max_pixel_clock: u32 align(2),

        reserved0: [189]u8,

        comptime {
            //@compileLog(@sizeOf(Mode));
            assert(@sizeOf(Mode) == 0x100);
        }

        pub const MemoryModel = enum(u8) {
            text_mode = 0x00,
            cga_graphics = 0x01,
            hercules_graphics = 0x02,
            planar = 0x03,
            packed_pixel = 0x04,
            non_chain_4_256_color = 0x05,
            direct_color = 0x06,
            yuv = 0x07,
            _,
        };

        pub const Attributes = packed struct(u16) {
            mode_supported_by_hardware: bool,
            reserved: u1 = 0,
            TTY_output_function_supported_by_BIOS: bool,
            color: bool,
            graphics: bool,
            vga_incompatible: bool,
            vga_incompatible_window_mode: bool,
            linear_framebuffer: bool,
            double_scan_mode: bool,
            interlaced_mode: bool,
            hardware_triple_buffering: bool,
            hardware_stereoscopic_display: bool,
            dual_display_start_address: bool,
            reserved0: u3 = 0,
        };

        pub const Number = packed struct(u16) {
            number: u8,
            is_VESA: bool,
            reserved: u2 = 0,
            refresh_rate_control_select: bool,
            reserved0: u2 = 0,
            linear_flat_frame_buffer_select: bool,
            preserve_display_memory_select: bool,
        };

        pub fn defaultIsValid(mode: *const VBE.Mode) bool {
            return mode.memory_model == .direct_color and mode.mode_attributes.linear_framebuffer;
        }
    };

    const ReturnValue = enum(u8) {
        successful = 0,
        failure = 1,
        not_supported_in_hardware = 2,
        invalid_in_current_video_mode = 3,
    };

    const Call = enum(u8) {
        get_controller_information = 0x00,
        get_mode_information = 0x01,
        set_mode_information = 0x02,
        get_edid_information = 0x15,
    };

    const interrupt_number = 0x10;
    const vbe_code = 0x4f;

    pub fn VBEinterrupt(call: Call, registers: *Registers) !void {
        const source_ax = @as(u16, vbe_code << 8) | @enumToInt(call);
        registers.eax = source_ax;
        interrupt(interrupt_number, registers, registers);

        const ax = @truncate(u16, registers.eax);
        const al = @truncate(u8, ax);
        const is_supported = al == vbe_code;
        if (!is_supported) return Error.not_supported;

        const ah = @truncate(u8, ax >> 8);
        if (ah > 3) @panic("Return value too high");
        const return_value = @intToEnum(ReturnValue, ah);
        return switch (return_value) {
            .failure => Error.failure,
            .not_supported_in_hardware => Error.not_supported_in_hardware,
            .invalid_in_current_video_mode => Error.invalid_in_current_video_mode,
            .successful => {},
        };
    }

    pub fn getControllerInformation(vbe_info: *VBE.Information) VBE.Error!void {
        var registers = Registers{};

        registers.edi = @ptrToInt(vbe_info);
        try VBEinterrupt(.get_controller_information, &registers);
    }

    pub const Error = error{
        bad_signature,
        unsupported_version,
        not_supported,
        failure,
        not_supported_in_hardware,
        invalid_in_current_video_mode,
    };

    const EDID = extern struct {
        padding: [8]u8,
        manufacturer_id_be: u16 align(1),
        edid_id_code: u16 align(1),
        serial_number: u32 align(1),
        man_week: u8,
        man_year: u8,
        edid_version: u8,
        edid_revision: u8,
        video_input_type: u8,
        max_horizontal_size: u8,
        max_vertical_size: u8,
        gamma_factor: u8,
        dpms_flags: u8,
        chroma_info: [10]u8,
        est_timings1: u8,
        est_timings2: u8,
        man_res_timing: u8,
        std_timing_id: [8]u16 align(1),
        det_timing_desc1: [18]u8,
        det_timing_desc2: [18]u8,
        det_timing_desc3: [18]u8,
        det_timing_desc4: [18]u8,
        unused: u8,
        checksum: u8,

        comptime {
            assert(@sizeOf(EDID) == 0x80);
        }

        pub fn getWidth(edid: *const EDID) u16 {
            return edid.det_timing_desc1[2] + (@as(u16, edid.det_timing_desc1[4] & 0xf0) << 4);
        }

        pub fn getHeight(edid: *const EDID) u16 {
            return edid.det_timing_desc1[5] + (@as(u16, edid.det_timing_desc1[7] & 0xf0) << 4);
        }
    };

    pub fn getEDIDInfo() VBE.Error!EDID {
        var edid_info: EDID = undefined;

        var registers = Registers{};
        registers.ds = segment(@ptrToInt(&edid_info));
        registers.es = registers.ds;
        registers.edi = offset(@ptrToInt(&edid_info));
        registers.ebx = 1;

        try VBEinterrupt(.get_edid_information, &registers);

        return edid_info;
    }

    pub fn setVideoMode(video_mode_number: u16) VBE.Error!void {
        var registers = Registers{};
        registers.ebx = @as(u32, video_mode_number) | (1 << 14);
        try VBEinterrupt(.set_mode_information, &registers);
    }
};
