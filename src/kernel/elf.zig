const common = @import("common");
const align_forward = common.align_forward;
const assert = common.assert;
const copy = common.copy;
const ELF = common.ELF;
const is_aligned = common.is_aligned;
const log = common.log.scoped(.ELF);
const string_eq = common.string_eq;

const RNU = @import("RNU");
const Executable = RNU.Executable;
const PhysicalAddressSpace = RNU.PhysicalAddressSpace;
const TODO = RNU.TODO;
const VirtualAddress = RNU.VirtualAddress;
const VirtualAddressSpace = RNU.VirtualAddressSpace;

const kernel = @import("kernel");

const arch = @import("arch");

pub const ELFResult = struct {
    entry_point: u64,
};

pub fn is_elf(file: []const u8) bool {
    const file_header = @ptrCast(*const ELF.FileHeader, @alignCast(@alignOf(ELF.FileHeader), file.ptr));
    return file_header.is_valid(file_header);
}

const Error = error{
    program_header_not_page_aligned,
    program_header_offset_not_page_aligned,
    no_sections,
};

pub fn load_into_kernel_memory(file: []const u8) !Executable.InKernelMemory {
    //for (file) |byte, byte_i| {
    //log.debug("[{}] = 0x{x}", .{ byte_i, byte });
    //}
    const file_header = @ptrCast(*const ELF.FileHeader, @alignCast(@alignOf(ELF.FileHeader), file.ptr));
    if (!file_header.is_valid()) @panic("Trying to load as ELF file a corrupted ELF file");

    assert(file_header.program_header_size == @sizeOf(ELF.ProgramHeader));
    assert(file_header.section_header_size == @sizeOf(ELF.SectionHeader));
    // TODO: further checking
    log.debug("SH entry count: {}. PH entry count: {}", .{ file_header.section_header_entry_count, file_header.program_header_entry_count });
    log.debug("SH size: {}. PH size: {}", .{ file_header.section_header_size, file_header.program_header_size });
    const program_headers = @intToPtr([*]const ELF.ProgramHeader, @ptrToInt(file_header) + file_header.program_header_offset)[0..file_header.program_header_entry_count];

    var result = Executable.InKernelMemory{
        .entry_point = file_header.entry,
    };

    for (program_headers) |*ph| {
        switch (ph.type) {
            .load => {
                if (ph.size_in_memory == 0) continue;

                const page_size = arch.page_size;
                const misalignment = ph.virtual_address & (page_size - 1);
                const base_virtual_address = VirtualAddress.new(ph.virtual_address - misalignment);
                const segment_size = align_forward(ph.size_in_memory + misalignment, page_size);

                if (misalignment != 0) {
                    return Error.program_header_not_page_aligned;
                }

                if (!is_aligned(ph.offset, page_size)) {
                    return Error.program_header_offset_not_page_aligned;
                }

                if (kernel.config.safe_slow) {
                    assert(ph.flags.readable);
                    assert(ph.size_in_file <= ph.size_in_memory);
                    assert(misalignment == 0);
                    assert(kernel.virtual_address_space.translate_address(base_virtual_address) == null);
                }

                const kernel_segment_virtual_address = try kernel.virtual_address_space.allocate(segment_size, null, .{ .write = true });
                const dst_slice = kernel_segment_virtual_address.offset(misalignment).access([*]u8)[0..ph.size_in_memory];
                const src_slice = @intToPtr([*]const u8, @ptrToInt(file.ptr) + ph.offset)[0..ph.size_in_file];
                assert(dst_slice.len >= src_slice.len);
                copy(u8, dst_slice, src_slice);

                if (result.section_count < result.sections.len) {
                    const section = &result.sections[result.section_count];
                    section.* = Executable.Section{
                        .user_address = base_virtual_address,
                        .kernel_address = kernel_segment_virtual_address,
                        .size = segment_size,
                        .flags = .{ .execute = ph.flags.executable, .write = ph.flags.writable, .user = true },
                    };

                    log.debug("New section: {}", .{section});

                    result.section_count += 1;
                } else {
                    @panic("Can't load executable because section count exceeds the ones supported");
                }
            },
            else => {
                log.debug("Unhandled PH type: {}", .{ph.type});
            },
        }
    }

    if (result.section_count == 0) {
        return Error.no_sections;
    }

    return result;
}
