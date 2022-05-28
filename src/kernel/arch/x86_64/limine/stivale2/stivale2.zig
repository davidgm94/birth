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

pub fn process_memory_map(memory_map_struct: *align(1) stivale.Struct.MemoryMap) []kernel.Memory.Map.Entry {
    const memory_map_entries = memory_map_struct.memmap()[0..memory_map_struct.entry_count];
    var slice_result: []kernel.Memory.Map.Entry = undefined;

    // First, it is required to find a spot in memory big enough to host all the memory map entries in a architecture-independent and bootloader-independent way. This is the host entry
    const host_entry = blk: {
        for (memory_map_entries) |*entry| {
            if (entry.type == .usable) {
                const bitset = kernel.Memory.Map.Entry.get_bitset_from_address_and_size(entry.address, entry.size);
                const bitset_size = bitset.len * @sizeOf(kernel.Memory.Map.Entry.BitsetBaseType);
                // INFO: this is separated since the bitset needs to be in a different page than the memory map
                const bitset_page_count = kernel.bytes_to_pages(bitset_size, false);
                const memory_map_allocation_size = memory_map_struct.entry_count * @sizeOf(kernel.Memory.Map.Entry);
                const memory_map_page_count = kernel.bytes_to_pages(memory_map_allocation_size, false);
                const total_allocated_page_count = bitset_page_count + memory_map_page_count;
                const total_allocation_size = kernel.arch.page_size * total_allocated_page_count;
                kernel.assert(@src(), entry.size > total_allocation_size);
                slice_result = @intToPtr([*]kernel.Memory.Map.Entry, entry.address + kernel.align_forward(bitset_size, kernel.arch.page_size))[0..memory_map_struct.entry_count];
                var result = &slice_result[0];
                result.* = kernel.Memory.Map.Entry{
                    .region = kernel.Memory.Region.Descriptor{
                        .address = entry.address,
                        .size = entry.size,
                    },
                    .allocated_page_count = 0,
                    .type = .usable,
                };

                result.setup_bitset(total_allocated_page_count);

                break :blk result;
            }
        }

        @panic("There is no memory map entry big enough to store the memory map entries");
    };

    // The counter starts with one because we have already filled the memory map with the host entry
    var entry_i: u64 = 1;
    for (std.enums.values(kernel.Memory.Map.Entry.Type)) |entry_type| {
        for (memory_map_entries) |*entry| {
            if (entry.address == host_entry.region.address) continue;

            const resolved_entry_type: kernel.Memory.Map.Entry.Type = switch (entry.type) {
                .usable => .usable,
                .reserved => .reserved,
                .kernel_and_modules => .kernel_and_modules,
                .bootloader_reclaimable => .bootloader_reclaimable,
                .framebuffer => .framebuffer,
                else => kernel.panic("Not implemented: {}", .{entry.type}),
            };

            if (entry_type == resolved_entry_type) {
                var result_entry = &slice_result[entry_i];
                result_entry.* = kernel.Memory.Map.Entry{
                    .region = kernel.Memory.Region.Descriptor{
                        .address = entry.address,
                        .size = entry.size,
                    },
                    .allocated_page_count = 0,
                    .type = resolved_entry_type,
                };

                entry_i += 1;

                // Setup the bitset
                if (resolved_entry_type == .usable) {
                    const bitset = result_entry.get_bitset();
                    const bitset_size = bitset.len * @sizeOf(kernel.Memory.Map.Entry.BitsetBaseType);
                    // INFO: this is separated since the bitset needs to be in a different page than the memory map
                    const bitset_page_count = kernel.bytes_to_pages(bitset_size, false);
                    result_entry.setup_bitset(bitset_page_count);
                }
            }
        }
    }

    return slice_result;
}
