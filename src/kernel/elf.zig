const std = @import("../common/std.zig");

const arch = @import("arch/common.zig");
const crash = @import("crash.zig");
const PhysicalAddressSpace = @import("physical_address_space.zig");
const PhysicalMemoryRegion = @import("physical_memory_region.zig");
const VirtualAddress = @import("virtual_address.zig");
const VirtualAddressSpace = @import("virtual_address_space.zig");

const TODO = crash.TODO;
const log = std.log.scoped(.ELF);

const FileHeader = extern struct {
    // e_ident
    magic: u8 = magic,
    elf_id: [3]u8 = elf_signature.*,
    bit_count: Bits = .b64,
    endianness: Endianness = .little,
    header_version: u8 = 1,
    os_abi: ABI = .SystemV,
    abi_version: u8 = 0,
    padding: [7]u8 = [_]u8{0} ** 7,
    object_type: ObjectFileType = .executable, // e_type
    machine: Machine = .AMD64,
    version: u32 = 1,
    entry: u64,
    program_header_offset: u64 = 0x40,
    section_header_offset: u64,
    flags: u32 = 0,
    header_size: u16 = 0x40,
    program_header_size: u16 = @sizeOf(ProgramHeader),
    program_header_entry_count: u16 = 1,
    section_header_size: u16 = @sizeOf(SectionHeader),
    section_header_entry_count: u16,
    name_section_header_index: u16,

    const magic = 0x7f;
    const elf_signature = "ELF";
    const Bits = enum(u8) {
        b32 = 1,
        b64 = 2,
    };

    const Endianness = enum(u8) {
        little = 1,
        big = 2,
    };

    const ABI = enum(u8) {
        SystemV = 0,
    };

    const ObjectFileType = enum(u16) {
        none = 0,
        relocatable = 1,
        executable = 2,
        dynamic = 3,
        core = 4,
        lo_os = 0xfe00,
        hi_os = 0xfeff,
        lo_proc = 0xff00,
        hi_proc = 0xffff,
    };

    const Machine = enum(u16) {
        AMD64 = 0x3e,
    };
};

const ProgramHeader = extern struct {
    type: Type = .load,
    flags: Flags, //= @enumToInt(Flags.readable) | @enumToInt(Flags.executable),
    offset: u64,
    virtual_address: u64,
    physical_address: u64,
    size_in_file: u64,
    size_in_memory: u64,
    alignment: u64 = 0,

    const Type = enum(u32) {
        @"null" = 0,
        load = 1,
        dynamic = 2,
        interpreter = 3,
        note = 4,
        shlib = 5, // reserved
        program_header = 6,
        tls = 7,
        lo_os = 0x60000000,
        gnu_eh_frame = 0x6474e550,
        gnu_stack = 0x6474e551,
        hi_os = 0x6fffffff,
        lo_proc = 0x70000000,
        hi_proc = 0x7fffffff,
        _,
    };

    const Flags = packed struct {
        executable: bool,
        writable: bool,
        readable: bool,
        reserved: u29,

        comptime {
            std.assert(@sizeOf(Flags) == @sizeOf(u32));
        }
    };
};

const SectionHeader = extern struct {
    name_offset: u32,
    type: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    // section index
    link: u32,
    info: u32,
    alignment: u64,
    entry_size: u64,

    // type
    const ID = enum(u32) {
        @"null" = 0,
        program_data = 1,
        symbol_table = 2,
        string_table = 3,
        relocation_entries_addends = 4,
        symbol_hash_table = 5,
        dynamic_linking_info = 6,
        notes = 7,
        program_space_no_data = 8,
        relocation_entries = 9,
        reserved = 10,
        dynamic_linker_symbol_table = 11,
        array_of_constructors = 14,
        array_of_destructors = 15,
        array_of_pre_constructors = 16,
        section_group = 17,
        extended_section_indices = 18,
        number_of_defined_types = 19,
        start_os_specific = 0x60000000,
    };

    const Flag = enum(u64) {
        writable = 0x01,
        alloc = 0x02,
        executable = 0x04,
        mergeable = 0x10,
        contains_null_terminated_strings = 0x20,
        info_link = 0x40,
        link_order = 0x80,
        os_non_conforming = 0x100,
        section_group = 0x200,
        tls = 0x400,
        mask_os = 0x0ff00000,
        mask_processor = 0xf0000000,
        ordered = 0x4000000,
        exclude = 0x8000000,
    };
};

pub const ELFResult = struct {
    entry_point: u64,
};

pub const ElfAddressSpaces = struct {
    kernel: *VirtualAddressSpace,
    user: *VirtualAddressSpace,
    physical: *PhysicalAddressSpace,
};

pub fn load(address_spaces: ElfAddressSpaces, file: []const u8) ELFResult {
    //for (file) |byte, byte_i| {
    //log.debug("[{}] = 0x{x}", .{ byte_i, byte });
    //}
    const file_header = @ptrCast(*const FileHeader, @alignCast(@alignOf(FileHeader), file.ptr));
    if (file_header.magic != FileHeader.magic) @panic("magic");
    if (!std.string_eq(&file_header.elf_id, FileHeader.elf_signature)) @panic("signature");
    std.assert(file_header.program_header_size == @sizeOf(ProgramHeader));
    std.assert(file_header.section_header_size == @sizeOf(SectionHeader));
    const entry_point = file_header.entry;
    // TODO: further checking
    log.debug("SH entry count: {}. PH entry count: {}", .{ file_header.section_header_entry_count, file_header.program_header_entry_count });
    log.debug("SH size: {}. PH size: {}", .{ file_header.section_header_size, file_header.program_header_size });
    const program_headers = @intToPtr([*]const ProgramHeader, @ptrToInt(file_header) + file_header.program_header_offset)[0..file_header.program_header_entry_count];

    for (program_headers) |*ph| {
        switch (ph.type) {
            .load => {
                if (ph.size_in_memory == 0) continue;

                log.debug("Segment virtual address: (0x{x}, 0x{x})", .{ ph.virtual_address, ph.virtual_address + ph.size_in_memory });

                const page_size = arch.page_size;
                const misalignment = ph.virtual_address & (page_size - 1);
                const base_virtual_address = VirtualAddress.new(ph.virtual_address - misalignment);
                const segment_size = std.align_forward(ph.size_in_memory + misalignment, page_size);

                if (!ph.flags.writable) {
                    if (misalignment != 0) {
                        @panic("ELF file with misaligned segments");
                    }

                    if (!std.is_aligned(ph.offset, page_size)) {
                        @panic("ELF file with misaligned offset");
                    }

                    std.assert(ph.flags.readable);

                    std.assert(address_spaces.kernel.translate_address(base_virtual_address) == null);
                    std.assert(address_spaces.user.translate_address(base_virtual_address) == null);

                    const page_count = @divExact(segment_size, page_size);
                    const physical_region = address_spaces.physical.allocate_pages(page_size, page_count, .{ .zeroed = true }) orelse @panic("physical");
                    const kernel_segment_virtual_address = physical_region.address.to_higher_half_virtual_address();
                    // Giving executable permissions here to perform the copy
                    std.assert(std.is_aligned(physical_region.size, arch.page_size));
                    address_spaces.kernel.map(physical_region.address, kernel_segment_virtual_address, physical_region.size / arch.page_size, .{ .write = true }) catch unreachable;
                    // TODO: load segments and then take the right settings from the sections
                    // .write attribute is just wrong here, but it avoids page faults when writing to the bss section
                    address_spaces.user.map(physical_region.address, base_virtual_address, physical_region.size / arch.page_size, .{ .execute = ph.flags.executable, .write = !ph.flags.executable, .user = true }) catch unreachable;
                    std.assert(ph.size_in_file <= ph.size_in_memory);
                    std.assert(misalignment == 0);
                    const dst_slice = kernel_segment_virtual_address.offset(misalignment).access([*]u8)[0..ph.size_in_memory];
                    const src_slice = @intToPtr([*]const u8, @ptrToInt(file.ptr) + ph.offset)[0..ph.size_in_file];
                    std.assert(dst_slice.len >= src_slice.len);

                    std.copy(u8, dst_slice, src_slice);
                    log.debug("Last byte: 0x{x}", .{dst_slice[dst_slice.len - 1]});
                    // TODO: unmap
                } else {
                    TODO();
                }
            },
            else => {
                log.debug("Unhandled PH type: {}", .{ph.type});
            },
        }
        //if (ph.type == .load) {
        //}
    }

    return ELFResult{
        .entry_point = entry_point,
    };
}
