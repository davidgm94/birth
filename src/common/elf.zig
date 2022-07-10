const common = @import("../common.zig");
const context = @import("context");

const TODO = common.TODO;
const log = common.log.scoped(.ELF);
const VirtualAddress = common.VirtualAddress;
const VirtualAddressSpace = common.VirtualAddressSpace;
const PhysicalAddressSpace = common.PhysicalAddressSpace;
const PhysicalMemoryRegion = common.PhysicalMemoryRegion;

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
            common.comptime_assert(@sizeOf(Flags) == @sizeOf(u32));
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

pub fn parse(address_spaces: ElfAddressSpaces, file: []const u8) ELFResult {
    const file_header = @ptrCast(*const FileHeader, @alignCast(@alignOf(FileHeader), file.ptr));
    if (file_header.magic != FileHeader.magic) @panic("magic");
    if (!common.string_eq(&file_header.elf_id, FileHeader.elf_signature)) @panic("signature");
    common.runtime_assert(@src(), file_header.program_header_size == @sizeOf(ProgramHeader));
    common.runtime_assert(@src(), file_header.section_header_size == @sizeOf(SectionHeader));
    // TODO: further checking
    log.debug("SH entry count: {}. PH entry count: {}", .{ file_header.section_header_entry_count, file_header.program_header_entry_count });
    log.debug("SH size: {}. PH size: {}", .{ file_header.section_header_size, file_header.program_header_size });
    const program_headers = @intToPtr([*]const ProgramHeader, @ptrToInt(file_header) + file_header.program_header_offset)[0..file_header.program_header_entry_count];

    for (program_headers) |*ph| {
        switch (ph.type) {
            .load => {
                if (ph.size_in_memory == 0) continue;

                const page_size = context.page_size;
                const misalignment = ph.virtual_address & (page_size - 1);
                const base_virtual_address = VirtualAddress.new(ph.virtual_address - misalignment);
                const segment_size = common.align_forward(ph.size_in_memory + misalignment, page_size);
                _ = segment_size;
                _ = base_virtual_address;

                if (!ph.flags.writable) {
                    if (misalignment != 0) {
                        @panic("ELF file with misaligned segments");
                    }

                    if (!common.is_aligned(ph.offset, page_size)) {
                        @panic("ELF file with misaligned offset");
                    }

                    common.runtime_assert(@src(), ph.flags.readable);

                    common.runtime_assert(@src(), address_spaces.kernel.translate_address(base_virtual_address) == null);
                    common.runtime_assert(@src(), address_spaces.user.translate_address(base_virtual_address) == null);
                    const page_count = common.bytes_to_pages(segment_size, page_size, .must_be_exact);
                    const physical = address_spaces.physical.allocate(page_count) orelse @panic("physical");
                    const physical_region = PhysicalMemoryRegion.new(physical, segment_size);
                    const kernel_segment_virtual_address = physical.to_higher_half_virtual_address();
                    // Giving executable permissions here to perform the copy
                    address_spaces.kernel.map_physical_region(physical_region, kernel_segment_virtual_address, .{ .write = true });
                    const dst_slice = kernel_segment_virtual_address.offset(misalignment).access([*]u8)[0..ph.size_in_memory];
                    const src_slice = @intToPtr([*]const u8, @ptrToInt(file.ptr) + ph.offset)[0..ph.size_in_file];
                    common.copy(u8, dst_slice, src_slice);
                    // TODO: unmap
                    address_spaces.user.map_physical_region(physical_region, base_virtual_address, .{ .execute = ph.flags.executable, .write = ph.flags.writable, .user = true });
                } else {
                    TODO(@src());
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
        .entry_point = file_header.entry,
    };
}
