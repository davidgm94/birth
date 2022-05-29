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
                log.debug("Size: {}", .{entry.size});
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
                    .region = kernel.Memory.Region.Descriptor{
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
            if (entry.address == host_entry.region.address) continue;

            log.debug("Entry type: {}. Entry size: {}", .{ entry.type, entry.size });
            const index = result.usable.len;
            result.usable.len += 1;
            var result_entry = &result.usable[index];
            result_entry.* = kernel.Memory.Map.Entry{
                .region = kernel.Memory.Region.Descriptor{
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
            log.debug("Entry type: {}. Entry size: {}", .{ entry.type, entry.size });
            const index = result.reclaimable.len;
            log.debug("index: {}", .{index});
            result.reclaimable.len += 1;
            var result_entry = &result.reclaimable[index];
            result_entry.* = kernel.Memory.Map.Entry{
                .region = kernel.Memory.Region.Descriptor{
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
            log.debug("Entry type: {}. Entry size: {}", .{ entry.type, entry.size });
            const index = result.framebuffer.len;
            log.debug("index: {}", .{index});
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
            log.debug("Entry type: {}. Entry size: {}", .{ entry.type, entry.size });
            const index = result.kernel_and_modules.len;
            log.debug("index: {}", .{index});
            result.kernel_and_modules.len += 1;
            var result_entry = &result.kernel_and_modules[index];
            result_entry.* = kernel.Memory.Region.Descriptor{
                .address = entry.address,
                .size = entry.size,
            };

            // Don't use the bitset here because it would imply using memory that may not be usable at the moment of writing the bitset to this region
        }
    }

    result.reserved.ptr = @intToPtr(@TypeOf(result.reserved.ptr), @ptrToInt(result.kernel_and_modules.ptr) + (@sizeOf(kernel.Memory.Region.Descriptor) * result.kernel_and_modules.len));

    for (memory_map_entries) |*entry| {
        if (entry.type == .reserved) {
            log.debug("Entry type: {}. Entry size: {}", .{ entry.type, entry.size });
            const index = result.reserved.len;
            log.debug("index: {}", .{index});
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
