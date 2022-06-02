const std = @import("std");
const assert = std.debug.assert;
const stivale = @import("header.zig");
const log = std.log.scoped(.stivale2);
const kernel = @import("../../../../kernel.zig");
pub const Struct = stivale.Struct;

pub fn find(comptime StructT: type, info: *align(1) stivale.Struct) ?*align(1) StructT {
    var tag_opt = @intToPtr(?*align(1) stivale.Tag, info.tags);

    while (tag_opt) |tag| {
        if (tag.identifier == StructT.id) {
            return @ptrCast(*align(1) StructT, tag);
        }

        tag_opt = @intToPtr(?*align(1) stivale.Tag, tag.next);
    }

    return null;
}

pub fn process_memory_map(memory_map_struct: *align(1) stivale.Struct.MemoryMap) kernel.Memory.Map {
    const memory_map_entries = memory_map_struct.memmap()[0..memory_map_struct.entry_count];
    var result = kernel.Memory.Map{
        .usable = &[_]kernel.Memory.Map.Entry{},
        .reclaimable = &[_]kernel.Memory.Map.Entry{},
        .framebuffer = &[_]kernel.Memory.Region.Descriptor{},
        .kernel_and_modules = &[_]kernel.Memory.Region.Descriptor{},
        .reserved = &[_]kernel.Memory.Region.Descriptor{},
    };

    // First, it is required to find a spot in memory big enough to host all the memory map entries in a architecture-independent and bootloader-independent way. This is the host entry
    const host_entry = blk: {
        for (memory_map_entries) |*entry| {
            if (entry.type == .usable) {
                const bitset = kernel.Memory.Map.Entry.get_bitset_from_address_and_size(entry.address, entry.size);
                const bitset_size = bitset.len * @sizeOf(kernel.Memory.Map.Entry.BitsetBaseType);
                // INFO: this is separated since the bitset needs to be in a different page than the memory map
                const bitset_page_count = kernel.bytes_to_pages(bitset_size, false);
                // Allocate a bit more memory than needed just in case
                const memory_map_allocation_size = memory_map_struct.entry_count * @sizeOf(kernel.Memory.Map.Entry);
                const memory_map_page_count = kernel.bytes_to_pages(memory_map_allocation_size, false);
                const total_allocated_page_count = bitset_page_count + memory_map_page_count;
                const total_allocation_size = kernel.arch.page_size * total_allocated_page_count;
                kernel.assert(@src(), entry.size > total_allocation_size);
                result.usable = @intToPtr([*]kernel.Memory.Map.Entry, entry.address + kernel.align_forward(bitset_size, kernel.arch.page_size))[0..1];
                var block = &result.usable[0];
                block.* = kernel.Memory.Map.Entry{
                    .descriptor = kernel.Memory.Region.Descriptor{
                        .address = entry.address,
                        .size = entry.size,
                    },
                    .allocated_size = 0,
                    .type = .usable,
                };

                block.setup_bitset(total_allocated_page_count);

                break :blk block;
            }
        }

        @panic("There is no memory map entry big enough to store the memory map entries");
    };

    // The counter starts with one because we have already filled the memory map with the host entry
    for (memory_map_entries) |*entry| {
        if (entry.type == .usable) {
            if (entry.address == host_entry.descriptor.address) continue;

            const index = result.usable.len;
            result.usable.len += 1;
            var result_entry = &result.usable[index];
            result_entry.* = kernel.Memory.Map.Entry{
                .descriptor = kernel.Memory.Region.Descriptor{
                    .address = entry.address,
                    .size = entry.size,
                },
                .allocated_size = 0,
                .type = .usable,
            };

            result_entry.setup_bitset_alone();
        }
    }

    result.reclaimable.ptr = @intToPtr(@TypeOf(result.reclaimable.ptr), @ptrToInt(result.usable.ptr) + (@sizeOf(kernel.Memory.Map.Entry) * result.usable.len));

    for (memory_map_entries) |*entry| {
        if (entry.type == .bootloader_reclaimable) {
            const index = result.reclaimable.len;
            result.reclaimable.len += 1;
            var result_entry = &result.reclaimable[index];
            result_entry.* = kernel.Memory.Map.Entry{
                .descriptor = kernel.Memory.Region.Descriptor{
                    .address = entry.address,
                    .size = entry.size,
                },
                .allocated_size = 0,
                .type = .reclaimable,
            };

            // Don't use the bitset here because it would imply using memory that may not be usable at the moment of writing the bitset to this region
        }
    }

    result.framebuffer.ptr = @intToPtr(@TypeOf(result.framebuffer.ptr), @ptrToInt(result.reclaimable.ptr) + (@sizeOf(kernel.Memory.Map.Entry) * result.reclaimable.len));

    for (memory_map_entries) |*entry| {
        if (entry.type == .framebuffer) {
            const index = result.framebuffer.len;
            result.framebuffer.len += 1;
            var result_entry = &result.framebuffer[index];
            result_entry.* = kernel.Memory.Region.Descriptor{
                .address = entry.address,
                .size = entry.size,
            };

            // Don't use the bitset here because it would imply using memory that may not be usable at the moment of writing the bitset to this region
        }
    }

    result.kernel_and_modules.ptr = @intToPtr(@TypeOf(result.kernel_and_modules.ptr), @ptrToInt(result.framebuffer.ptr) + (@sizeOf(kernel.Memory.Region.Descriptor) * result.framebuffer.len));

    for (memory_map_entries) |*entry| {
        if (entry.type == .kernel_and_modules) {
            const index = result.kernel_and_modules.len;
            result.kernel_and_modules.len += 1;
            var result_entry = &result.kernel_and_modules[index];
            result_entry.* = kernel.Memory.Region.Descriptor{
                .address = entry.address,
                .size = entry.size,
            };

            // Don't use the bitset here because it would imply using memory that may not be usable at the moment of writing the bitset to this region
        }
    }

    kernel.assert(@src(), result.kernel_and_modules.len == 1);

    result.reserved.ptr = @intToPtr(@TypeOf(result.reserved.ptr), @ptrToInt(result.kernel_and_modules.ptr) + (@sizeOf(kernel.Memory.Region.Descriptor) * result.kernel_and_modules.len));

    for (memory_map_entries) |*entry| {
        if (entry.type == .reserved) {
            const index = result.reserved.len;
            result.reserved.len += 1;
            var result_entry = &result.reserved[index];
            result_entry.* = kernel.Memory.Region.Descriptor{
                .address = entry.address,
                .size = entry.size,
            };

            // Don't use the bitset here because it would imply using memory that may not be usable at the moment of writing the bitset to this region
        }
    }

    return result;
}

pub fn print_all_tags(info: *align(1) stivale.Struct) void {
    var tag_opt = @intToPtr(?*align(1) stivale.Tag, info.tags);

    while (tag_opt) |tag| {
        const tag_identifier = @intToEnum(stivale.StructTagID, tag.identifier);
        switch (tag_identifier) {
            .command_line,
            .fb_mtrr,
            .memory_map,
            .framebuffer,
            .boot_volume,
            .text_mode,
            .dtb,
            .mmio32uart,
            .pxe,
            .smp,
            .smbios,
            .efi_system_table,
            .firmware,
            .epoch,
            .rsdp,
            .terminal,
            .edid,
            => {},

            //.pmrs => {},
            //.kernel_file => {},
            //.kernel_filev2 => {},
            //.kernel_base_address => {},
            //.kernel_slide => {},
            //.modules => {},
            //.hhdm => {},

            .pmrs,
            .kernel_file,
            .kernel_filev2,
            .kernel_base_address,
            .kernel_slide,
            .modules,
            .hhdm,
            => {
                log.debug("Found {s}", .{@tagName(tag_identifier)});
                switch (tag_identifier) {
                    .pmrs => {
                        const pmrs_struct = @ptrCast(*align(1) stivale.Struct.PMRs, tag);
                        const pmrs = pmrs_struct.pmrs()[0..pmrs_struct.entry_count];
                        for (pmrs) |pmr| {
                            log.debug("PMR {}", .{pmr});
                        }
                    },
                    .kernel_file => {},
                    .kernel_base_address => {},
                    .kernel_filev2 => {
                        const kernel_file = @ptrCast(*align(1) stivale.Struct.KernelFileV2, tag);
                        kernel.file_physical_address = kernel_file.kernel_file;
                        kernel.file_size = kernel_file.kernel_size;
                        log.debug("Kernel file: (0x{x}, {})", .{ kernel_file.kernel_file, kernel_file.kernel_size });
                    },
                    .kernel_slide => {
                        const kernel_slide = @ptrCast(*align(1) stivale.Struct.KernelSlide, tag);
                        log.debug("Kernel slide: {}", .{kernel_slide});
                    },
                    .modules => {
                        const modules = @ptrCast(*align(1) stivale.Struct.Modules, tag);
                        log.debug("Kernel modules: {}", .{modules});
                    },
                    .hhdm => {
                        const hhdm = @ptrCast(*align(1) stivale.Struct.HHDM, tag);
                        log.debug("HHDM: 0x{x}", .{hhdm.addr});
                    },
                    else => unreachable,
                }
            },
        }
        tag_opt = @intToPtr(?*align(1) stivale.Tag, tag.next);
    }
}

pub fn process_pmrs(stivale2_struct: *stivale.Struct) void {
    const pmrs_struct = find(stivale.Struct.PMRs, stivale2_struct) orelse @panic("PMRs are required for RNU");
    const pmrs = pmrs_struct.pmrs()[0..pmrs_struct.entry_count];
    const kernel_sections_ptr = kernel.PhysicalMemory.allocate_pages(1) orelse @panic("can't allocate memory for kernel sections");
    const kernel_sections = @intToPtr([*]kernel.Memory.Region.DescriptorWithPermissions, kernel_sections_ptr)[0..pmrs.len];

    for (pmrs) |pmr, i| {
        const kernel_section = &kernel_sections[i];
        kernel_section.descriptor.address = pmr.address;
        kernel_section.descriptor.size = pmr.size;
        const permissions = pmr.permissions;
        kernel_section.read = permissions & (1 << stivale.Struct.PMRs.PMR.readable) != 0;
        kernel_section.write = permissions & (1 << stivale.Struct.PMRs.PMR.writable) != 0;
        kernel_section.execute = permissions & (1 << stivale.Struct.PMRs.PMR.executable) != 0;
    }

    kernel.sections_in_memory = kernel_sections;
}
pub fn process_kernel_file(stivale2_struct: *stivale.Struct) void {
    const kernel_file = find(stivale.Struct.KernelFileV2, stivale2_struct) orelse @panic("kernel file stivale struct is required for RNU");
    const file_address = kernel_file.kernel_file;
    const file_size = kernel_file.kernel_size;
    for (kernel.PhysicalMemory.map.reclaimable) |*region| {
        if (region.descriptor.address <= file_address and region.descriptor.address + region.descriptor.size > file_address) {
            kernel.assert(@src(), region.descriptor.size > file_size);
            var should_move_kernel_file = false;

            const bitset_size = region.get_bitset().len * @sizeOf(kernel.Memory.Map.Entry.BitsetBaseType);
            const file_offset = file_address - region.descriptor.address;
            if (bitset_size >= file_offset) {
                should_move_kernel_file = true;
            }
            const space_after = region.descriptor.size - file_offset;
            if (space_after < file_size) {
                should_move_kernel_file = true;
            }
            if (bitset_size + file_size > region.descriptor.size) {
                should_move_kernel_file = true;
            }
            if (should_move_kernel_file) {
                const kernel_page_count = kernel.bytes_to_pages(file_size, false);
                const allocation = kernel.PhysicalMemory.allocate_pages(kernel_page_count) orelse @panic("Couldn't allocate pages for kernel file move");
                const dst = @intToPtr([*]u8, allocation)[0..file_size];
                const src = @intToPtr([*]u8, file_address)[0..file_size];
                log.debug("Copying kernel file...", .{});
                kernel.copy(u8, dst, src);
                kernel.file_physical_address = @ptrToInt(dst.ptr);
                kernel.file_size = file_size;
            } else {
                @panic("ni");
                // The kernel must be in charge of creating the bitset for this region and populating it with the pages used by the kernel file
            }

            return;
        }
    }

    @panic("unable to find kernel file memory region");
}
